# Security

Report vulnerabilities privately through GitHub security advisories. Do not post
private keys, passwords, PINs or confidential molecular projects in issues.

This is an initial implementation without an independent security audit.
Automated tests exercise the container, access policies and mocked PIV protocol.
Real hardware behavior must be validated on each supported OS/device combination
before relying on a YubiKey as the sole recovery method.

The plugin encrypts exported files. It does not encrypt application memory,
swap, ordinary saves, backups or data handled by other plugins. Python does not
guarantee complete erasure of secrets from memory. Authenticated decryption
must finish before any project data is passed to MoleditPy.

YubiKey support only reads certificates and invokes private-key operations.
No key generation, provisioning, PIN changes or device resets are performed.
PIN failures are not retried automatically.
