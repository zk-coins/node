FROM rust:1.81-bookworm AS builder
WORKDIR /app

# Install SP1 toolchain (needed by build.rs to compile the program ELF for riscv32)
RUN curl -L https://sp1up.succinct.xyz | bash && \
    /root/.sp1/bin/sp1up && \
    TOOLCHAIN_BIN=$(dirname $(rustup +succinct which rustc)) && \
    ln -sf $(which cargo) "$TOOLCHAIN_BIN/cargo"

COPY . .
RUN cargo build --release -p server

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates wget && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/server /usr/local/bin/zkcoins-server

ENV RUST_LOG=info
EXPOSE 4242

ENTRYPOINT ["zkcoins-server"]
