# Step 1: Build the binary with musl
FROM rust:1.82-slim AS builder

# Install necessary dependencies for MUSL build and Sui CLI
RUN apt-get update && \
    apt-get install -y musl-tools pkg-config libssl-dev curl git unzip

# Add musl target
RUN rustup target add x86_64-unknown-linux-musl

RUN apt-get update && apt-get install -y --no-install-recommends \
    clang \
    llvm-dev \
    libclang-dev \
    pkg-config \
    libssl-dev \
    cmake \
    make \
    gcc \
    g++ \
 && rm -rf /var/lib/apt/lists/*

# Install Sui CLI from Git (main branch)
RUN cargo install --locked \
    --git https://github.com/MystenLabs/sui.git \
    --tag mainnet-v1.47.1 \
    sui \
    --features tracing

# Make Sui CLI available system-wide
ENV PATH="/root/.cargo/bin:${PATH}"

# Create app directory
WORKDIR /app

# Copy source files
COPY . .

# Optional: Create .cargo/config.toml to enforce static linking (needed for OpenSSL sometimes)
# Uncomment if needed:
# RUN mkdir -p .cargo && \
#     echo '[target.x86_64-unknown-linux-musl]\nrustflags = ["-C", "target-feature=+crt-static"]' > .cargo/config.toml

# Build statically-linked binary
RUN cargo build --release --target x86_64-unknown-linux-musl

# Step 2: Create minimal runtime image
FROM alpine:latest

# Install ca-certificates if your binary needs to make HTTPS requests
RUN apk add --no-cache ca-certificates

# Set working directory
WORKDIR /app

# Copy the built binary from builder stage
COPY --from=builder /app/target/x86_64-unknown-linux-musl/release/mothrbox .

# Optionally copy Sui CLI if you need it at runtime too
COPY --from=builder /root/.cargo/bin/sui /usr/local/bin/sui

# Run the binary
CMD ["./mothrbox"]
