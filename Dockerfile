# Use the official Rust image
FROM rust:1.81 AS builder

# Install musl tools
RUN rustup target add x86_64-unknown-linux-musl

# Set the working directory
WORKDIR /usr/src/app

# Copy your code
COPY . .

# Build the app in release mode
RUN cargo build --release

# Use a lightweight final image
FROM debian:buster-slim

# Create a new user to run your app
RUN useradd -m appuser

# Copy the compiled binary from builder
COPY --from=builder /usr/src/app/target/release/mothrbox /usr/local/bin/mothrbox

# Set permissions
RUN chown appuser:appuser /usr/local/bin/mothrbox

# Switch to the new user
USER appuser

# Run the binary
CMD ["mothrbox"]
