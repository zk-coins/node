FROM rust:1.81-bookworm AS builder
WORKDIR /app
COPY . .

# Remove script crate (requires SP1 succinct toolchain not available in Docker)
# The server uses SP1_PROVER=mock which doesn't need the actual prover
RUN sed -i '/"script",/d' Cargo.toml
RUN cargo build --release -p server

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates wget && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/server /usr/local/bin/zkcoins-server

ENV RUST_LOG=info
ENV SP1_PROVER=mock
EXPOSE 4242

ENTRYPOINT ["zkcoins-server"]
