# Step 1: Build the binary with musl
FROM rust:1.81 AS builder

# Install necessary dependencies for MUSL build
RUN apt-get update && apt-get install -y musl-tools pkg-config libssl-dev

# Add musl target
RUN rustup target add x86_64-unknown-linux-musl

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

# Run the binary
CMD ["./mothrbox"]
