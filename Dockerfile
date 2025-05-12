# Step 1: Builder with musl for static binary
FROM rust:1.82-alpine as builder

# Install dependencies and set up environment for static binary with musl
RUN apk update && apk add --no-cache \
    curl \
    git \
    unzip \
    cmake \
    make \
    gcc \
    g++ \
    pkgconfig \
    musl-dev \
    clang \
    llvm-dev \
    libclang \
    openssl-dev \
    && rustup component add rustfmt \
    && rustup target add x86_64-unknown-linux-musl

# Install Sui CLI from GitHub repository
RUN cargo install --locked \
  --git https://github.com/MystenLabs/sui.git \
  --tag mainnet-v1.47.1 \
  sui \
  --features tracing \
  --target x86_64-unknown-linux-musl

# Copy application source and build it
WORKDIR /app
COPY . .

# Optional: force static linking (OpenSSL sometimes requires it)
# Uncomment to enable static linking if needed
# RUN mkdir -p .cargo && echo '[target.x86_64-unknown-linux-musl]\nrustflags = ["-C", "target-feature=+crt-static"]' > .cargo/config.toml

RUN cargo build --release --target x86_64-unknown-linux-musl

# Step 2: Copy to runtime image
FROM debian:bullseye-slim

# Install runtime dependencies (e.g., ca-certificates)
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy the compiled application and Sui CLI binary from the builder image
COPY --from=builder /app/target/x86_64-unknown-linux-musl/release/mothrbox .
COPY --from=builder /root/.cargo/bin/sui /usr/local/bin/sui

# Command to run the application
CMD ["./mothrbox"]
