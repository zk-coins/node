FROM rust:1.81-bookworm AS builder
WORKDIR /app
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
RUN apt-get update && apt-get install -y ca-certificates wget && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/server /usr/local/bin/zkcoins-server

ENV RUST_LOG=info
WORKDIR /data
EXPOSE 4242

ENTRYPOINT ["zkcoins-server"]
