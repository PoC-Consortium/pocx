# pocx_verifier

Plot file integrity verification tool with multiple verification modes.

## Features

- **Multiple Verification Modes**: Single, partial, random, and complete verification  
- **Hash Verification**: Validates plot file integrity using pocx_hashlib
- **Progress Tracking**: Built-in progress bars with indicatif
- **CLI Interface**: Comprehensive command-line interface

## Build

```bash
# Standard build
cargo build --release -p pocx_verifier

# Run tests
cargo test -p pocx_verifier
```

## Verification Modes

- **single**: Verify one specific nonce and scoop combination
- **partial**: Verify a sample of nonces from the plot file
- **random**: Continuously verify random nonces (endless)
- **complete**: Verify the entire plot file (full validation)

## License

MIT License - See [LICENSE](../LICENSE) for details.
