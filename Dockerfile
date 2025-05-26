# Build stage
FROM rust:bookworm AS builder

WORKDIR /app
COPY . .
RUN apt-get update && apt-get install -y pkg-config libssl-dev ca-certificates
RUN cargo build --release

# Final run stage
FROM debian:bookworm-slim AS runner

# Install OpenSSL 3 (libssl3) and CA certs
RUN apt-get update && apt-get install -y libssl3 ca-certificates && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /app/target/release/mothrbox_service_core /app/mothrbox_service_core
CMD ["/app/mothrbox_service_core"]
