# Build stage
FROM rust:bookworm AS builder
 
WORKDIR /app
COPY . .
RUN cargo build --release
 
# Final run stage
FROM debian:bookworm-slim AS runner
 
WORKDIR /app
COPY --from=builder /app/mothrbox_service_core/release/mothrbox_service_core /app/mothrbox_service_core
CMD ["/app/example-rust"]