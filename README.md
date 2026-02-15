# cUtils
coreUtils-consoleUtils-cloudUtils-cyberUtils cryptUtils cyberUtils

## zerotrust-drive

FUSE-based encrypted overlay filesystem. You work with decrypted files in the mount directory
while all data is stored encrypted at rest using ChaCha20-Poly1305 AEAD encryption (the `.age`
file extension is a naming convention — not the age crate).

Google Drive never sees plaintext file names or content. The encrypted storage directory
contains only opaque files (`000001.age`, `000002.age`, ...) and an encrypted index
(`_index.age`) that maps them to their real names. Point `--encrypted-dir` at a Google Drive
sync folder and Google Drive handles upload/sync of the ciphertext automatically.

This is an in-memory filesystem — all file content is held in RAM while open.
Not recommended for files larger than available memory.

If the encrypted storage is modified externally (e.g. by cloud sync) while mounted,
zerotrust-drive detects the conflict, logs a warning, and preserves the in-memory state.
Unmount and remount to pick up external changes.

### Prerequisites

Requires [macFUSE](https://macfuse.github.io/) to be installed.

### Usage

    just mount                                          # mount with default paths
    just mount encrypted_dir=~/gdrive/zt                # point storage at Google Drive folder
    ZEROTRUST_PASSPHRASE="my-secret" just mount         # mount with a custom passphrase
    just umount                                         # unmount the filesystem
    just test                                           # run unit tests
    just release                                        # build optimized release binary
    just clean                                          # remove build artifacts and encrypted storage

Default paths: `target/.encrypted.disk` (storage) and `target/decrypted.disk` (mount).
Both are overridable via justfile variables or CLI flags `--encrypted-dir` / `--decrypted-dir`.

The encrypted storage directory (`target/.encrypted.disk`) is auto-managed by zerotrust-drive.
Do not modify or touch its contents directly.

### Encryption

zerotrust-drive uses ChaCha20-Poly1305, an AEAD (Authenticated Encryption with Associated
Data) cipher standardized by the IETF in RFC 8439. It provides both confidentiality and
integrity — if a file is tampered with or corrupted (e.g. during cloud sync), decryption
fails rather than silently returning garbage.

The same cipher is used by WireGuard, TLS 1.3, SSH (OpenSSH), Google's QUIC protocol, and
Android disk encryption. It is a 256-bit cipher considered equally secure to AES-256.

Apple FileVault uses AES-XTS, which is designed for fixed-size disk sectors and does not
provide authentication. ChaCha20-Poly1305 is a better fit for file-level encryption with
cloud sync because its built-in authentication detects corruption or tampering automatically.
