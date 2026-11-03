# Encrypted Project Pro for MoleditPy

[![Tests](https://github.com/HiroYokoyama/moleditpy_encrypted_project_pro/actions/workflows/test.yml/badge.svg)](https://github.com/HiroYokoyama/moleditpy_encrypted_project_pro/actions/workflows/test.yml)
[![GitHub tag](https://img.shields.io/github/v/tag/HiroYokoyama/moleditpy_encrypted_project_pro?label=version)](https://github.com/HiroYokoyama/moleditpy_encrypted_project_pro/tags)
[![GitHub Downloads](https://img.shields.io/github/downloads/HiroYokoyama/moleditpy_encrypted_project_pro/total)](https://github.com/HiroYokoyama/moleditpy_encrypted_project_pro/releases)
[![License: LGPL v3](https://img.shields.io/badge/License-LGPLv3-blue.svg)](LICENSE)

Save encrypted molecular projects as **`.pmeecp`** using a folder plugin for
MoleditPy 5. The format is separate from the basic plugin's `.pmeenc` files.
All encryption and decryption runs locally.

## Install

Use Python 3.10–3.14 with MoleditPy 5 and PySide6. In that Python environment:

```sh
python -m pip install "cryptography>=46,<52"
```

Copy the complete `encrypted_project_pro/` folder into `~/.moleditpy/plugins/`
(`%USERPROFILE%\.moleditpy\plugins\` on Windows), then restart MoleditPy.
The packaged plugin ZIP can also be installed through Plugin Manager.
Third-party libraries are installed separately and are not in the ZIP.

## Save and open

1. Choose **File → Export → Encrypted Project Pro (.pmeecp)...**.
2. Add **Password**, confirm a unique passphrase of at least 12 characters,
   and save. Or add key-based methods from the same dialog.
3. Open the encrypted file through File Open or
   **File → Open Encrypted Project Pro...**. Supply the requested credentials.

The policy selector offers:

| Policy | Meaning |
| --- | --- |
| Any one method | Any registered method can open the file. Add recovery alternatives here. |
| All methods | Every listed method is required. Losing any one makes the file unrecoverable. |

Only one of these policies applies to a file; up to eight methods can be listed.
Different methods should use independent credentials. There is no backdoor,
password reset, or automatic recovery. Keep backups of your keys and files.

| Method | Supported credentials |
| --- | --- |
| Password | Confirmed passphrase; scrypt derives the wrapping key. |
| Key file | Exactly 32 random bytes. Create one with **File → Generate encryption key file...**; keep it separately. Existing keys are never overwritten. |
| Public/private key | PEM public key or certificate to save; matching PEM private key to open, including passphrase-protected PKCS#8 keys. RSA 2048/3072/4096, X25519, and ECDH P-256. |
| YubiKey PIV | Device-generated RSA or P-256 key and matching certificate in PIV slot **9d**, with PIN Once/Always and Touch Always. |

Encryption with a public key does not require possession of its private key.
Encryption does not authenticate the sender. Public-key recipients should only
open projects from sources they trust.

## YubiKey

Install the optional SDK in the same environment:

```sh
python -m pip install "yubikey-manager>=5.9,<6" "cryptography>=46,<49"
```

The SDK currently requires cryptography below 49. Linux also needs a running
PC/SC service and the appropriate device permissions; building pyscard can require
PC/SC development headers. Windows/macOS need functioning smart-card support.

Prepare the PIV encryption key and certificate with Yubico's tools first.
The plugin requires readable slot metadata, device-generated keys, PIN policy
Once/Always, and touch policy Always. Connect exactly one YubiKey when saving.
When opening, its serial and public-key fingerprint must match the file.
Enter the **PIV PIN**, then touch the key. FIDO-only Security Keys, OTP, FIDO2
credentials and challenge-response slots are not supported by this version.

The plugin never provisions keys, changes PINs, resets a device or retries a
failed PIN automatically. Automated tests exercise real SDK interfaces using
mock devices and real RSA/ECDH operations. Physical devices have not yet been
validated; do not rely on an untested token as your only recovery method.

## Security and file behavior

AES-256-GCM authenticates the encrypted project and its header. Each export
uses a fresh random data key and nonce. Each method wraps that key independently
in Any mode; All mode wraps independent XOR shares whose combination recovers
the data key. Password wrapping uses scrypt (N=131072, r=8, p=1), a random
16-byte salt, and AES-GCM. Public keys use RSA-OAEP-SHA256 or ephemeral
X25519/P-256 agreement with HKDF-SHA256 and AES-GCM.

The versioned container records its policy, method types, salts, nonces,
public-key fingerprints and YubiKey routing metadata in cleartext. Molecular
project data and registered plugin state are encrypted. Passwords, PINs,
private keys, key-file contents and their paths are not stored in the header.
Public headers are authenticated only after successful decryption.

Files are limited to 64 MiB of project JSON and a 64 KiB header. Malformed
headers are rejected before key derivation. Successful encryption is written
atomically using an encrypted temporary file; no plaintext temporary project
is created. Authentication failure never passes data to the host.

An opened project becomes an **unsaved document**. Ordinary Save does not
overwrite the `.pmeecp` file. Use the encrypted Export action to save encrypted
again; ordinary application saves remain ordinary, unencrypted saves. Saving
an encrypted export does not clear the host's unsaved-document flag.

This plugin protects exported files, not application memory, swap, ordinary
saves, backups, other plugins or a compromised computer. Python cannot guarantee
complete erasure of secrets from memory. This initial implementation has not
received an independent security audit. See SECURITY.md.

## Development

```sh
python -m pip install -e ".[test,yubikey]"
python -m pytest
python -m ruff check encrypted_project_pro tests
python scripts/release_common.py package --version 0.1.1
```

Tests cover encryption, Any/All access requirements, wrong keys, authenticated
header and payload tampering, size limits, atomic-write failures, real Qt
import/export flows, and the optional PIV interface without hardware access.
CI runs on Windows, macOS and Linux. The ZIP contains the folder plugin,
README, LGPL/GPL texts and licensing notice; no wheels are distributed.

## License

LGPL-3.0-or-later. See LICENSE, COPYING and LICENSING.md. Dependency licenses
remain separate; no third-party binaries or private key material are shipped.
