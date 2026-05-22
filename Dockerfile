# Multi-stage Docker build for the zkCoins server post Plonky2 migration.
#
# The Plonky2 toolchain pin is `nightly` (see `rust-toolchain` at the
# repo root). rustup respects that file and installs the right channel
# automatically when cargo is first invoked — no manual `rustup install`
# step needed.
#
# Build:
#   docker build -t zkcoin/server:latest .
#   docker build -t zkcoin/server:beta .
#
# Both DEV (`:beta`) and PRD (`:latest`) ship the MVP-only binary
# (no Cargo features beyond the always-on mint route). The `FEATURES`
# build-arg below stays in place as an opt-in escape hatch for self-
# hosters who want to compile non-MVP routes locally (e.g.
# `--build-arg FEATURES=usernames,lnurl`).
# Run:
#   docker run -p 4242:4242 \
#     -e ESPLORA_URL=http://electrs:3000 \
#     -e PUBLISHER_KEY=<hex> \
#     -v zkcoins-data:/data \
#     zkcoin/server:latest

FROM rust:bookworm AS builder
WORKDIR /app

# `sqlx::migrate!("./migrations")` is compile-time, so the migrations
# directory must exist when `cargo build` runs (the COPY below pulls
# it in). The current `db.rs` uses runtime-checked `sqlx::query` /
# `sqlx::query_as`, so no `.sqlx/` offline cache is needed; setting
# `SQLX_OFFLINE=true` is defensive — if a future change introduces a
# compile-checked `sqlx::query!` macro, the build will surface the
# missing `.sqlx/` immediately rather than trying (and failing) to
# reach a live database from the builder.
ENV SQLX_OFFLINE=true

# Copy just the toolchain file first so rustup can fetch the right
# channel before the slow source copy. Cuts a few seconds off cold
# builds; layer-caches well across source-only changes.
COPY rust-toolchain ./
RUN rustup show

COPY . .

# Cargo features for non-MVP routes. Empty by default — both DEV and
# PRD images ship the MVP-only feature set so the two environments run
# the identical binary. Self-hosters who want to enable non-MVP routes
# in a local build can pass a comma-separated list
# (e.g. `--build-arg FEATURES=usernames,lnurl`). Features not listed
# here are excluded from the binary at compile time, so the disabled
# code cannot run, crash, or be exploited at runtime.
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
