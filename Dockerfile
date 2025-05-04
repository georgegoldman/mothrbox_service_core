# Step 1: Build the binary with musl
FROM rust:1.81 as builder

# Install musl tools
RUN rustup target add x86_64-unknown-linux-musl

WORKDIR /app
COPY . .

# Build statically-linked binary
RUN cargo build --release --target x86_64-unknown-linux-musl

# Step 2: Create minimal runtime image
FROM alpine:latest

WORKDIR /app
COPY --from=builder /app/target/x86_64-unknown-linux-musl/release/mothrbox .

# Run the binary
CMD ["./mothrbox"]
