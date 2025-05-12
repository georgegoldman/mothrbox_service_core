# Step 1: Build the binary with musl
FROM rust:1.82-slim AS builder

# Install necessary dependencies for MUSL build and Sui CLI
RUN apt-get update && \
    apt-get install -y musl-tools pkg-config libssl-dev curl git unzip \
    clang llvm-dev libclang-dev cmake make gcc g++ && \
    rm -rf /var/lib/apt/lists/*

# Add musl target for statically linking the build
RUN rustup target add x86_64-unknown-linux-musl

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

# Copy Cargo.toml and Cargo.lock for dependency caching
COPY Cargo.toml ./

# Fetch dependencies before copying the entire source to leverage Docker cache
RUN cargo fetch

# Now copy the source files
COPY . .

# Optional: Create .cargo/config.toml to enforce static linking (needed for OpenSSL sometimes)
# Uncomment if needed:
# RUN mkdir -p .cargo && \
#     echo '[target.x86_64-unknown-linux-musl]\nrustflags = ["-C", "target-feature=+crt-static"]' > .cargo/config.toml

# Build statically-linked binary for musl target
RUN cargo build --release --target x86_64-unknown-linux-musl

# Step 2: Create minimal runtime image
FROM alpine:latest

# Install ca-certificates if your binary needs to make HTTPS requests
RUN apk add --no-cache ca-certificates

# Set working directory for runtime
WORKDIR /app

# Copy the built binary from the builder stage
COPY --from=builder /app/target/x86_64-unknown-linux-musl/release/mothrbox .

# Optionally copy Sui CLI if you need it at runtime too
COPY --from=builder /root/.cargo/bin/sui /usr/local/bin/sui

# Run the binary
CMD ["./mothrbox"]
