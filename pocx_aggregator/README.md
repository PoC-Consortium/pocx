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
- Ideal for solo mining to a local wallet/node

## Configuration

The aggregator is configured via `aggregator_config.yaml`. A working template is shipped alongside the binary (`pocx_aggregator/aggregator_config.yaml`).

```yaml
# Server configuration for downstream miner connections
server:
  # Address to listen on for miner connections (default: 0.0.0.0:8080)
  listen_address: "0.0.0.0:8080"

  # Optional Basic auth for downstream miner connections
  auth:
    enabled: false
    # basic_auth:
    #   username: "aggregator"
    #   password: "secret"

# Upstream pool or wallet configuration
upstream:
  name: "primary_pool"

  # Transport: http (default) or https
  rpc_transport: http
  rpc_host: "pool.example.com"
  rpc_port: 8080

  # Authentication for the upstream:
  #   type: none                                  -> no auth
  #   type: user_pass, username: ..., password: ... -> HTTP Basic
  #   type: cookie, cookie_path: "/path/.cookie"    -> Bitcoin Core cookie file
  rpc_auth:
    type: none

  # Per-account best (pool) or global best (wallet)
  submission_mode: pool

  # Expected block time in seconds (PoCX: 120, Burst: 240). Default: 120.
  block_time_secs: 120

# Cache settings
cache:
  # How long to cache mining info, in seconds (default: 5)
  mining_info_ttl_secs: 5
  # Upstream request timeout, in seconds (default: 30)
  pool_timeout_secs: 30

# Database settings
database:
  # SQLite file path (default: aggregator.db)
  path: "aggregator.db"
  # Retention in days, 0 = keep forever (default: 7)
  retention_days: 7

# Dashboard (optional - omit the whole block to disable)
dashboard:
  enabled: true
  listen_address: "0.0.0.0:8081"

# Logging
logging:
  # trace | debug | info | warn | error  (default: info)
  level: "info"
  # Log file path (default: aggregator.log)
  file: "aggregator.log"
```

### Upstream auth examples

```yaml
# HTTPS pool with username/password
upstream:
  name: "pocx_pool"
  rpc_transport: https
  rpc_host: "pool.pocx.io"
  rpc_port: 443
  rpc_auth:
    type: user_pass
    username: "aggregator"
    password: "your-password"
  submission_mode: pool
  block_time_secs: 120

# Local Bitcoin-PoCX node using cookie auth (solo / wallet mode)
upstream:
  name: "local_node"
  rpc_transport: http
  rpc_host: "127.0.0.1"
  rpc_port: 18332
  rpc_auth:
    type: cookie
    cookie_path: 'C:\Users\YourName\AppData\Local\Bitcoin-PoCX\testnet\.cookie'
  submission_mode: wallet
  block_time_secs: 120
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

# Or with a custom config path
./target/release/pocx_aggregator --config /path/to/aggregator_config.yaml
```

## Pointing miners at the aggregator

The aggregator looks like any other upstream to `pocx_miner`. Configure a chain entry pointing at the aggregator's `server.listen_address`:

```yaml
# miner_config.yaml
chains:
  - name: 'Local Aggregator'
    rpc_transport: http
    rpc_host: '127.0.0.1'
    rpc_port: 8080
    rpc_auth:
      type: none           # or user_pass if server.auth.enabled = true
      # username: 'aggregator'
      # password: 'secret'
    block_time_seconds: 120
    submission_mode: pool   # must match the aggregator's upstream.submission_mode
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
