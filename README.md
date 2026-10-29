# padoracle

A concurrent CBC padding oracle tool. Decrypt a ciphertext, or forge one for a
chosen plaintext, against any HTTP padding oracle.

Standard library only. No installs, no dependencies. One file.

It exists because `padbuster` is single threaded, has no resume, and prints a Perl
warning on every run. `padoracle` searches the 256 candidates for each byte in
parallel, retries connection failures with backoff, checkpoints progress so you can
resume after Ctrl+C, and forges ciphertexts as well as decrypting them.

## Install

```
curl -O https://raw.githubusercontent.com/<you>/padoracle/main/padoracle.py
python3 padoracle.py --version
```

Python 3.8 or newer. Nothing else.

## Decrypt

```
python3 padoracle.py decrypt \
  --url "http://target/profile?token=^CT^" \
  --error "Padding error" \
  <ciphertext-hex>
```

The marker `^CT^` is where the ciphertext goes. It can live in the URL, a cookie, a
header, or the body:

```
# in a cookie
python3 padoracle.py decrypt --url http://target/app \
  --cookie "session=^CT^" --error "decryption failed" <ciphertext>

# in a POST body
python3 padoracle.py decrypt --url http://target/api \
  --data "data=^CT^&submit=1" --error "invalid" <ciphertext>
```

## Encrypt (forge)

Produce a ciphertext that decrypts to a plaintext you choose, no key required:

```
python3 padoracle.py encrypt \
  --url "http://target/app" --cookie "session=^CT^" \
  --error "decryption failed" \
  "role=admin"
```

The forged value is printed in the chosen encoding. Drop it into the same parameter.

## Telling valid from invalid padding

Pick one signal:

- `--error STRING`  the response contains STRING when padding is invalid
- `--valid STRING`  the response contains STRING when padding is valid
- `--invalid-status N`  HTTP status N means invalid padding

On decrypt the tool runs one preflight request with the real ciphertext and prints
whether the baseline reads as valid. If the real ciphertext reads invalid, the
signal is wrong and every byte will look valid; fix it before the real run.

## Options worth knowing

| flag | meaning | default |
|------|---------|---------|
| `--workers N` | parallel guesses per byte; lower it if the target drops connections | 16 |
| `--encoding` | `hex`, `base64`, or `base64url` | hex |
| `--urlencode` | URL-encode the injected value (needed for base64 in a query) | off |
| `--block-size N` | cipher block size in bytes | 16 |
| `--iv HEX` | explicit IV; without it the first block is treated as the IV | first block |
| `--state FILE` | checkpoint solved blocks; rerun the same command to resume | off |
| `--timeout / --retries / --backoff` | connection tuning for flaky targets | 15 / 5 / 3.0 |
| `--raw` | keep PKCS7 padding in the output | off |

If a fragile target keeps timing out, lower `--workers` to 4 or 2. Fewer parallel
connections often finishes faster than a flood the server keeps resetting.

## Use as a library

The attack engine is transport agnostic. Give it any callable that returns True on
valid padding:

```python
from padoracle import PaddingOracleAttack

def oracle(ciphertext: bytes) -> bool:
    ...  # return True when the padding is valid

attack = PaddingOracleAttack(oracle, block_size=16, workers=16)
plaintext = attack.decrypt(ciphertext)        # first block treated as IV
forged    = attack.encrypt(b"role=admin")     # forge a ciphertext
```

## Tests

```
python3 -m unittest -v
```

Engine tests model the block cipher with a hash, so they prove the decrypt and
encrypt math with no crypto library. A real AES over HTTP test also runs when
`pycryptodome` is installed, and self skips when it is not.

## Legal

For authorized testing, CTFs, and research only. You are responsible for having
permission to test the target.

## License

MIT. See LICENSE.
