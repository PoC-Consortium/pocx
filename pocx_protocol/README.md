# pocx_protocol

JSON-RPC 2.0 protocol implementation for PoCX mining operations with client and server support.

## Features

- **JSON-RPC 2.0 Compliant**: Full specification compliance with error mapping
- **Client & Server**: Mining client and trait-based server implementations  
- **Async/Await**: Built on tokio for modern async networking
- **Type Safety**: Strongly typed request/response structures
- **Authentication**: Optional bearer token authentication
- **Error Handling**: Comprehensive error types with JSON-RPC error codes

## Build

```bash
# Standard build
cargo build --release -p pocx_protocol

# Run tests
cargo test -p pocx_protocol
```

## Documentation

For detailed API reference and protocol specifications, see the [Wiki](../wiki/API-Reference.md).

## License

MIT License - See [LICENSE](../LICENSE) for details.