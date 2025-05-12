# Step 1: Builder with musl for static binary
FROM rust:1.82-slim as builder


RUN apt-get update && apt-get install -y \
    curl git unzip cmake make gcc g++ \
    pkg-config libssl-dev \
    musl-tools \
    clang llvm-dev libclang-dev \
    && rustup component add rustfmt \
    && rustup target add x86_64-unknown-linux-musl

# Install Sui CLI
RUN cargo install --locked \
  --git https://github.com/MystenLabs/sui.git \
  --tag mainnet-v1.47.1 \
  sui \
  --features tracing \
  --target x86_64-unknown-linux-musl

WORKDIR /app
COPY . .

# Optional: force static linking (OpenSSL sometimes requires it)
# RUN mkdir -p .cargo && echo '[target.x86_64-unknown-linux-musl]\nrustflags = ["-C", "target-feature=+crt-static"]' > .cargo/config.toml

RUN cargo build --release --target x86_64-unknown-linux-musl

# Step 2: Copy to runtime
FROM debian:bullseye-slim

RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /app/target/x86_64-unknown-linux-musl/release/mothrbox .
COPY --from=builder /root/.cargo/bin/sui /usr/local/bin/sui

CMD ["./mothrbox"]
