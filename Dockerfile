FROM rust:1.81-bookworm AS builder

# Install SP1 toolchain (required for program compilation)
RUN curl -L https://sp1up.succinct.xyz | bash && \
    /root/.sp1/bin/sp1up && \
    echo 'export PATH="/root/.sp1/bin:$PATH"' >> /root/.bashrc

ENV PATH="/root/.sp1/bin:${PATH}"

WORKDIR /app
COPY . .
RUN cargo build --release -p server

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates wget && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/server /usr/local/bin/zkcoins-server

ENV RUST_LOG=info
ENV SP1_PROVER=mock
EXPOSE 4242

ENTRYPOINT ["zkcoins-server"]
