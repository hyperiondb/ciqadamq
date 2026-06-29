FROM lukemathwalker/cargo-chef:latest-rust-alpine AS chef
WORKDIR /build

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
RUN apk add --no-cache build-base musl-dev pkgconfig openssl-dev openssl-libs-static protoc protobuf-dev
ENV OPENSSL_STATIC=1
COPY --from=planner /build/recipe.json recipe.json
# Vendored path deps must be present for `cargo chef cook` to resolve them.
COPY vendor/ vendor/
# Build and cache dependencies — this layer is only invalidated when recipe.json changes.
RUN cargo chef cook --release --recipe-path recipe.json
COPY . .
RUN cargo build --release

FROM alpine:3.23

RUN apk add --no-cache ca-certificates \
    && adduser -S -s /sbin/nologin ciqadamq
WORKDIR /app
COPY --from=builder /build/target/release/ciqadamq /usr/local/bin/ciqadamq
COPY config.toml ./config.toml
RUN mkdir -p /app/data && chown -R ciqadamq /app
USER ciqadamq

EXPOSE 1883 8083 8090

VOLUME /app/data

ENTRYPOINT ["/usr/local/bin/ciqadamq"]
CMD ["config.toml"]
