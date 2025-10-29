# pocx_aggregator

High-performance mining aggregator for the PoCX protocol. Acts as a proxy between multiple miners and a single upstream pool or wallet, aggregating submissions and distributing mining information efficiently.

## Features

- **High Concurrency**: Async/await architecture using Tokio for handling thousands of simultaneous miner connections
- **Protocol Compliant**: Full JSON-RPC 2.0 support via pocx_protocol
- **Submission Filtering**: Intelligent per-account or global best submission filtering
- **Statistics**: Real-time mining statistics and submission tracking
- **Web Dashboard**: Optional HTTP dashboard for monitoring aggregator status
- **Database**: SQLite-based submission tracking with configurable retention

## Architecture

The aggregator sits between miners and a single upstream pool/wallet:

```
[Miners] <--JSON-RPC--> [Aggregator] <--JSON-RPC--> [Upstream Pool/Wallet]
   |                         |
   +-- miner1               / \
   +-- miner2              /   \
   +-- miner3             /     \
   +-- ...               /       \
```

### Key Components

- **Miner Server**: Accepts connections from miners, serves mining info, accepts nonce submissions
- **Upstream Client**: Connects to single upstream pool/wallet, fetches mining info, forwards filtered submissions
- **Submission Queue**: Filters and queues submissions based on mode (Pool/Wallet)
- **Cache**: Caches mining info to reduce upstream load
- **Stats**: Tracks submissions, deadlines, and performance metrics
- **Database**: Stores submission history for statistics and analysis

## Submission Modes

### Pool Mode (Default)
- Tracks best submission **per account** for last 3 blocks
- Forwards submissions with retry and exponential backoff
- Ideal for aggregating submissions to mining pools

### Wallet Mode
- Tracks **global best** submission across all accounts for last 3 blocks
- No retry logic (fail fast)
- Ideal for solo mining to local wallet

## Configuration

Create an `aggregator_config.yaml` file:

```yaml
# Listen address for miner connections
listen_address: "0.0.0.0:8080"

# Expected block time in seconds
block_time_secs: 120

# Upstream pool or wallet
upstream:
  name: "primary-pool"
  url: "http://pool.example.com:8080/pocx"
  # Optional authentication token
  # auth_token: "your_token_here"
  # Submission mode: pool (default) or wallet
  submission_mode: pool

# Cache settings
cache:
  mining_info_ttl_secs: 5
  pool_timeout_secs: 30

# Database settings
database:
  path: "aggregator.db"
  retention_days: 7  # 0 = keep forever

# Statistics dashboard (optional)
dashboard:
  enabled: true
  listen_address: "0.0.0.0:8081"

# Logging
logging:
  level: "info"
  file: "aggregator.log"
```

## Build

```bash
# Build from workspace root
cargo build --release -p pocx_aggregator

# Or build in this directory
cargo build --release
```

## Run

```bash
# From workspace root
./target/release/pocx_aggregator -c aggregator_config.yaml

# Or with custom config path
./target/release/pocx_aggregator --config /path/to/aggregator_config.yaml
```

## Usage

Once running, point your miners to the aggregator:

```yaml
# miner_config.yaml
chains:
  - name: "aggregator"
    base_url: "http://localhost:8080"
    api_path: "/"
    accounts:
      - account: "your_account_id"
```

## Development

```bash
# Run tests
cargo test -p pocx_aggregator

# Run with debug logging
RUST_LOG=debug cargo run -p pocx_aggregator -- -c aggregator_config.yaml
```

## License

MIT License - See [LICENSE](../LICENSE) for details.
