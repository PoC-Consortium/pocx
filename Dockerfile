# Stage 1: Build
FROM rust:1.91-slim-bookworm as builder

RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    cmake \
    clang \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/pocx
COPY . .

# Build the workspace in release mode
RUN cargo build --release

# Stage 2: Runtime
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    libssl3 \
    ca-certificates \
    libopencl1 \
    ocl-icd-libopencl1 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy binaries from builder
COPY --from=builder /usr/src/pocx/target/release/pocx_miner /usr/local/bin/
COPY --from=builder /usr/src/pocx/target/release/pocx_plotter /usr/local/bin/
COPY --from=builder /usr/src/pocx/target/release/pocx_plotter_v2 /usr/local/bin/
COPY --from=builder /usr/src/pocx/target/release/pocx_verifier /usr/local/bin/
COPY --from=builder /usr/src/pocx/target/release/pocx_aggregator /usr/local/bin/
COPY --from=builder /usr/src/pocx/target/release/pocx_mockchain /usr/local/bin/

# Default command (can be overridden)
CMD ["pocx_miner", "--help"]
