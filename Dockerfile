# Step 1: Build your own app binary
FROM rust:1.82-slim AS builder

RUN apt-get update && \
    apt-get install -y musl-tools pkg-config libssl-dev curl git unzip

RUN rustup target add x86_64-unknown-linux-musl

# Set work directory
WORKDIR /app

# Copy only manifest first to leverage Docker cache
COPY Cargo.toml ./
RUN mkdir src && echo "fn main() {}" > src/main.rs
RUN cargo build --release --target x86_64-unknown-linux-musl
RUN rm -r src

# Copy actual source
COPY . .

# Build your binary
RUN cargo build --release --target x86_64-unknown-linux-musl

# Step 2: Create final minimal image
FROM alpine:latest

RUN apk add --no-cache ca-certificates curl

# Download prebuilt Sui CLI
RUN curl -L https://github.com/MystenLabs/sui/releases/download/mainnet-v1.47.1/sui -o /usr/local/bin/sui && \
    chmod +x /usr/local/bin/sui

WORKDIR /app

COPY --from=builder /app/target/x86_64-unknown-linux-musl/release/mothrbox .

CMD ["./mothrbox"]
