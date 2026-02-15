# cUtils
coreUtils-consoleUtils-cloudUtils-cyberUtils cryptUtils cyberUtils

## zerotrust-drive

FUSE-based encrypted filesystem that provides transparent encryption and decryption of files.
All data is encrypted at rest using ChaCha20-Poly1305 AEAD encryption. Applications interact
with it as a normal filesystem while the underlying storage is fully encrypted.

### Prerequisites

Requires [macFUSE](https://macfuse.github.io/) to be installed.

### Usage

    just mount                                          # build and mount the encrypted filesystem
    ZEROTRUST_PASSPHRASE="my-secret" just mount         # mount with a custom passphrase
    just unmount                                        # unmount the filesystem
    just test                                           # run unit tests
    just release                                        # build optimized release binary
    just clean                                          # remove build artifacts and encrypted storage
