# decrypt-mpegts

A command-line tool for decrypting HLS sample-encrypted MPEG-TS files.

Implements the [Apple HLS Sample Encryption](https://developer.apple.com/library/archive/documentation/AudioVideo/Conceptual/HLS_Sample_Encryption/) specification (SAMPLE-AES), where encryption is applied selectively at the elementary stream level rather than to the entire transport stream.

## Supported stream types

| Stream type | Encrypted byte | Standard byte |
|---|---|---|
| H.264 (AVC) | `0xDB` | `0x1B` |
| AAC (ADTS) | `0xCF` | `0x0F` |
| AC-3 | `0xC1` | `0x81` |

## How it works

1. Parses PAT/PMT to identify encrypted elementary stream PIDs
2. For each encrypted PID, concatenates all ES data across PES boundaries
3. Decrypts the full ES using stream-type-specific rules:
   - **H.264**: NAL types 1 and 5 only, EPB removal, 1:9 pattern (16 bytes encrypted, 144 skipped), IV resets per NAL
   - **AAC**: Per ADTS frame, skip header + 16 leader bytes, decrypt remaining complete 16-byte blocks
   - **AC-3**: Per syncframe, skip 16 leader bytes, decrypt remaining complete 16-byte blocks
4. Re-splits decrypted ES back into PES packets matching original boundaries
5. Patches PMT to restore standard stream type bytes
6. Writes the decrypted transport stream

All decryption uses AES-128-CBC with no padding.

## Installation

```
cargo install --path .
```

Or build from source:

```
cargo build --release
```

## Usage

```
decrypt-mpegts --input <file.ts> --output <decrypted.ts> --key <hex> [--iv <hex>] [-y]
```

### Arguments

| Argument | Description |
|---|---|
| `-i, --input` | Input MPEG-TS file |
| `-o, --output` | Output MPEG-TS file |
| `-k, --key` | AES-128 key (32 hex characters) |
| `--iv` | AES-128 IV (32 hex characters, defaults to all zeros) |
| `-y, --yes` | Overwrite output file without prompting |

### Example

```
decrypt-mpegts \
  --input encrypted.ts \
  --output decrypted.ts \
  --key 00112233445566778899aabbccddeeff \
  --iv 0fedcba9876543210fedcba987654321
```

### Logging

Set `RUST_LOG` for detailed output:

```
RUST_LOG=info decrypt-mpegts --input in.ts --output out.ts --key ...
```

## License

[BSD-2-Clause](LICENSE)
