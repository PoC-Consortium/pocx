# pocx_address

Address encoding and decoding library for PoCX with dual format support (Base58Check and Bech32). This is an example implementation for Bitcoin-style addresses - the PoCX framework works with any addressing scheme based on a 20-byte payload.

This crate provides encode/decode functionality plus a main function to generate random addresses for testing purposes.

## Usage Examples

```rust
use pocx_address::{encode_address, decode_address, NetworkId, crypto};

// Generate cryptographic keypair
let private_key = crypto::PrivateKey::generate_random();
let payload = private_key.to_public_key().to_address_payload();

// Base58Check format (examples - any version byte 0x00-0xFF supported)
let base58_addr = encode_address(&payload, NetworkId::Base58(0x55))?;
let testnet_addr = encode_address(&payload, NetworkId::Base58(0x7F))?;

// Bech32 format (examples - any HRP supported)
let bech32_addr = encode_address(&payload, NetworkId::Bech32("pocx".to_string()))?;
let test_bech32 = encode_address(&payload, NetworkId::Bech32("tpocx".to_string()))?;

// Decode addresses (auto-detects format)
let (decoded_payload, network_id) = decode_address(&base58_addr)?;
let (decoded_payload, network_id) = decode_address(&bech32_addr)?;
```

## Build and Test

```bash
# Build library
cargo build --release -p pocx_address

# Run tests
cargo test -p pocx_address

# Run address generator
cargo run -p pocx_address
```

The address generator outputs test addresses for development purposes.

## License

MIT License - See [LICENSE](../LICENSE) for details.