# CBM Vault (`cbm-tool vault`) — Wave 5Q

`cbm-tool vault` provides an encrypted key-value secret store housed inside a standard 85688-byte CBM container envelope.

## Design

- **Derived Format**: The vault reuses the 85688-byte CBM container envelope (byte 0 header, encrypted body) and the clean-room TEA core. It is **not** a vendor container and makes no vendor-compatibility claim.
- **Envelope Layout**:
  - Byte 0: Preserved header byte (`0x81` at init: encryption bit 7 set, version 1).
  - Bytes 1..85687: TEA-encrypted body (85687 bytes).
- **Plainized Body Layout**:
  - Bytes 0..7: FNV-1a 64 checksum over body bytes 8..85686.
  - Bytes 8..15: Magic string `"CBMVLT01"`.
  - Bytes 16..17: Format version (u16, currently `1`).
  - Bytes 18..19: Record count (u16, max `1024`).
  - Bytes 20..23: Reserved (u32, zero).
  - Bytes 24..: Records in insertion order (`u16 label_len`, `u16 value_len`, label, value).
  - Remainder: Zero padding.
- **Key & Security**:
  - Key loaded from `CBM_VAULT_KEY` (must be exactly 16 bytes). If unset, defaults to the public `TEA_NATIVE_KEY` with an explicit warning (obfuscation, not confidentiality).
  - Wrong key, tampered ciphertext, or checksum mismatch is refused immediately.

## CLI Usage

```bash
# Create an empty vault
cbm-tool vault init my.vault

# Store or update a record
cbm-tool vault put my.vault api_token secret123

# Retrieve a value
cbm-tool vault get my.vault api_token

# List records in insertion order
cbm-tool vault list my.vault

# Erase a record
cbm-tool vault erase my.vault api_token
```
