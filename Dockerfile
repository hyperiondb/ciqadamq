FROM rust:1.96-bookworm AS builder
RUN apt-get update && apt-get install -y --no-install-recommends protobuf-compiler && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo "fn main() {}" > src/main.rs && cargo build --release && rm -rf src
COPY src ./src
RUN touch src/main.rs && cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends libssl3 ca-certificates && rm -rf /var/lib/apt/lists/* \
    && useradd -r -s /usr/sbin/nologin ciqadamq
WORKDIR /app
COPY --from=builder /build/target/release/ciqadamq /usr/local/bin/ciqadamq
COPY config.toml ./config.toml
RUN mkdir -p /app/data && chown -R ciqadamq /app
USER ciqadamq
EXPOSE 1883 8083 8090
VOLUME /app/data
ENTRYPOINT ["/usr/local/bin/ciqadamq"]
CMD ["config.toml"]
