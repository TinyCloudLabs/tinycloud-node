# Build argument to select runtime base (default scratch)
ARG RUNTIME_BASE=scratch
# Optional: pass "dstack" to enable TEE support
ARG CARGO_FEATURES=""

FROM rust:alpine AS chef
RUN apk add --no-cache musl-dev pkgconfig openssl-dev openssl-libs-static g++ perl make
RUN cargo install cargo-chef
WORKDIR /app

FROM chef AS planner
COPY ./Cargo.lock ./
COPY ./Cargo.toml ./
COPY ./tinycloud-node-server/ ./tinycloud-node-server/
COPY ./tinycloud-auth/ ./tinycloud-auth/
COPY ./tinycloud-core/ ./tinycloud-core/
COPY ./tinycloud-sdk-rs/ ./tinycloud-sdk-rs/
COPY ./tinycloud-sdk-wasm/ ./tinycloud-sdk-wasm/
COPY ./dependencies/siwe/ ./dependencies/siwe/
COPY ./dependencies/siwe-recap/ ./dependencies/siwe-recap/
COPY ./dependencies/cacao/ ./dependencies/cacao/
COPY ./scripts/ ./scripts/
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
ARG CARGO_FEATURES=""
COPY --from=planner /app/recipe.json recipe.json
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/app/target \
    cargo chef cook --release --recipe-path recipe.json ${CARGO_FEATURES:+--features $CARGO_FEATURES}
COPY --from=planner /app/ ./
RUN chmod +x ./scripts/init-tinycloud-data.sh && ./scripts/init-tinycloud-data.sh
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/app/target \
    cargo build --release -p tinycloud-node ${CARGO_FEATURES:+--features $CARGO_FEATURES} && \
    cp /app/target/release/tinycloud /app/tinycloud
RUN addgroup -g 1000 tinycloud && adduser -u 1000 -G tinycloud -s /bin/sh -D tinycloud
RUN mkdir -p /scratch-tmp && chmod 1777 /scratch-tmp

# Runtime stage
FROM ${RUNTIME_BASE} AS runtime
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=builder /etc/passwd /etc/passwd
COPY --from=builder /etc/group /etc/group
COPY --from=builder --chown=tinycloud:tinycloud /app/tinycloud /tinycloud
COPY --from=builder --chown=tinycloud:tinycloud /app/data ./data
COPY ./tinycloud.toml ./
COPY --from=builder /scratch-tmp /tmp
USER tinycloud:tinycloud
ENV ROCKET_ADDRESS=0.0.0.0
ENV TMPDIR=/data
EXPOSE 8000
EXPOSE 8001
EXPOSE 8081
ENTRYPOINT ["/tinycloud"]
LABEL org.opencontainers.image.source=https://github.com/TinyCloudLabs/tinycloud-node
