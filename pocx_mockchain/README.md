# pocx_mockchain

Mock blockchain simulator for PoCX testing and development with realistic mining simulation.

## Features

- **JSON-RPC 2.0 Server**: Compatible with PoCX mining clients
- **SQLite Database**: Persistent block and mining data storage  
- **Universal Network Support**: Configurable for any PoC cryptocurrency
- **Address Format Support**: Both Bech32 (modern) and Base58 (legacy) formats
- **Compression Support**: Configurable compression level ranges
- **TOML Configuration**: Clean, minimal configuration

## Quick Start

```bash
# Build the mockchain
cargo build --release -p pocx_mockchain

# Run with default configuration
./target/release/pocx_mockchain

# Server starts on localhost:8081
# JSON-RPC endpoint: http://localhost:8081/pocx
```

## Configuration

The mockchain uses `pocx_mockchain.toml` for configuration:

```toml
[network]
name = "PoCX Mockchain"

# Network ID determines address format
network_id = { Bech32 = "tpocx" }  # Modern format
# network_id = { Base58 = 127 }    # Legacy format

block_time_seconds = 120
minimum_compression_level = 1
target_compression_level = 1
genesis_signature = "0000000000000000000000000000000000000000000000000000000000000000"

[server]
host = "127.0.0.1"
port = 8081
enable_cors = true

[database]
url = "mockchain.db"
```

## Environment Variables

Override config file settings:

```bash
# Network configuration
POCX_NETWORK_ID="Bech32:custom" ./pocx_mockchain
POCX_NETWORK_ID="Base58:99" ./pocx_mockchain

# Server configuration  
POCX_HOST="0.0.0.0" POCX_PORT="8999" ./pocx_mockchain

# Other settings
POCX_DATABASE_URL="custom.db" ./pocx_mockchain
```

## Network Examples

```toml
# PoCX Testnet (default)
network_id = { Bech32 = "tpocx" }

# PoCX Mainnet  
network_id = { Bech32 = "pocx" }

# Legacy Base58 format
network_id = { Base58 = 127 }

# Custom network
network_id = { Bech32 = "mychain" }
```

## Mining Client Integration

The mockchain implements the standard PoC mining protocol:

- **getMiningInfo**: Returns current block info, compression requirements
- **submitNonce**: Accepts nonce submissions with quality validation
- **Automatic difficulty adjustment**: Based on block timing
- **Network capacity calculation**: Real-time network size estimation

Compatible with any PoC miner that supports the JSON-RPC 2.0 protocol.

## Development

```bash
# Run tests
cargo test -p pocx_mockchain

# Check code quality
cargo clippy -p pocx_mockchain

# Format code
cargo fmt -p pocx_mockchain
```