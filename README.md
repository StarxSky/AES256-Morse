# aes256-oii

A minimal C++ utility that encrypts plaintext with **AES-256-CBC** and encodes the ciphertext as a Morse-code-like string using `.` (dot), `-` (dash), and `_` (separator).

```
$ oiienc mysecret "Hello, World!"
_.-.-..._..---.._..-._..-_._...-.._...----_......_...-._...-._.---.._..---.._.--..._..--._..-.--_..-.--_...---_.--.._..-.-_..-._..-.--_..---._

$ oiienc mysecret "Hello, World!" | oiidec mysecret
Hello, World!
```

## How it works

1. A 256-bit key and 128-bit IV are deterministically derived from the password using SHA-256.
2. The plaintext is encrypted with **AES-256 in CBC mode** (PKCS#7 padding).
3. Each byte of the ciphertext is converted to 8 symbols — `.` for a `0` bit and `-` for a `1` bit (MSB first). Bytes are separated by `_`, producing a Morse-telegraph-like output.

Decoding reverses the process: the morse string is parsed back into bytes, then decrypted with the same password.

## Build

### Prerequisites

- CMake >= 3.14
- OpenSSL (libcrypto) — headers and shared library

### Build from source

```bash
cd aes256-oii
cmake -B build
cmake --build build
```

The binaries `oiienc` and `oiidec` are placed in `build/`.

### macOS (Homebrew)

```bash
brew install openssl cmake
cmake -B build -DOPENSSL_ROOT_DIR=$(brew --prefix openssl)
cmake --build build
```

## Usage

```
oiienc <password> [plaintext]
oiidec <password> [ciphertext]
```

If the text argument is omitted, the program reads from stdin — making piping easy:

```bash
# Pipe
oiienc mypassword "data" | oiidec mypassword

# File round-trip
oiienc mypassword "$(cat document.txt)" > encrypted.morse
oiidec mypassword "$(cat encrypted.morse)"

# Interactive (stdin)
oiienc mypassword
```

**Note:** A wrong password produces an error (AES padding validation will fail).

## Why dot/dash/underscore?

The three-character alphabet (`.`, `-`, `_`) was chosen to make ciphertext resemble classic Morse-code telegraph transmissions. Each byte is rendered as 8 dots/dashes, visually separated by underscores — giving the output a distinctive "wireless telegraph" aesthetic. The project name `oii` is retained for historical reasons.

## Security notes

- This is **real AES-256-CBC** encryption — not a toy cipher or obfuscation.
- The key derivation uses a single SHA-256 pass. For production use, consider replacing it with a proper KDF such as **PBKDF2**, **bcrypt**, or **Argon2** (the `derive_key_iv` function in `src/oiilib.hpp` is the only place that needs changing).
- The IV is deterministically derived from the password, so encrypting the same plaintext with the same password always produces the same output. This is **not semantically secure** for production; a random IV should be prefixed to the ciphertext in a real deployment.
- AES-CBC does not provide authenticity. Add an HMAC or use AES-GCM if tamper resistance is required.

## License

MIT
