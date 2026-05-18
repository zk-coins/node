# Multi-stage Docker build for the zkCoins server post Plonky2 migration.
#
# The Plonky2 toolchain pin is `nightly` (see `rust-toolchain` at the
# repo root). rustup respects that file and installs the right channel
# automatically when cargo is first invoked — no manual `rustup install`
# step needed.
#
# Build:
#   docker build -t zkcoin/server:latest .
#   docker build -t zkcoin/server:beta --build-arg FEATURES=address-list,faucet,usernames,lnurl .
# Run:
#   docker run -p 4242:4242 \
#     -e ESPLORA_URL=http://electrs:3000 \
#     -e PUBLISHER_KEY=<hex> \
#     -v zkcoins-data:/data \
#     zkcoin/server:latest

FROM rust:bookworm AS builder
WORKDIR /app

# Copy just the toolchain file first so rustup can fetch the right
# channel before the slow source copy. Cuts a few seconds off cold
# builds; layer-caches well across source-only changes.
COPY rust-toolchain ./
RUN rustup show

COPY . .

# Cargo features for non-MVP routes. Empty by default — the PRD image
# ships only the MVP feature set. The DEV image build passes a comma-
# separated list (e.g. `address-list,faucet,usernames,lnurl`). Features
# not listed here are excluded from the binary at compile time, so the
# disabled code cannot run, crash, or be exploited at runtime.
ARG FEATURES=
RUN if [ -z "$FEATURES" ]; then \
        cargo build --release -p server; \
    else \
        cargo build --release -p server --features "$FEATURES"; \
    fi

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates wget \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/server /usr/local/bin/zkcoins-server

ENV RUST_LOG=info
WORKDIR /data
EXPOSE 4242

ENTRYPOINT ["zkcoins-server"]
