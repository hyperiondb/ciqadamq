# syntax=docker/dockerfile:1
FROM rust:1.96-alpine AS builder

RUN apk add --no-cache build-base musl-dev pkgconfig openssl-dev openssl-libs-static protoc protobuf-dev
ENV OPENSSL_STATIC=1
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY vendor ./vendor
COPY src ./src
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/build/target \
    cargo build --release && cp target/release/ciqadamq /build/ciqadamq

FROM alpine:3.23

RUN apk add --no-cache ca-certificates \
    && adduser -S -s /sbin/nologin ciqadamq
WORKDIR /app
COPY --from=builder /build/ciqadamq /usr/local/bin/ciqadamq
COPY config.toml ./config.toml
RUN mkdir -p /app/data && chown -R ciqadamq /app
USER ciqadamq
EXPOSE 1883 8083 8090
VOLUME /app/data
ENTRYPOINT ["/usr/local/bin/ciqadamq"]
CMD ["config.toml"]
