FROM rust:alpine AS chef
RUN apk add --no-cache musl-dev pkgconfig openssl-dev openssl-libs-static
RUN cargo install cargo-chef
WORKDIR /app

FROM chef AS planner
COPY ./Cargo.lock ./
COPY ./Cargo.toml ./
COPY ./src/ ./src/
COPY ./tinycloud-lib/ ./tinycloud-lib/
COPY ./tinycloud-core/ ./tinycloud-core/
COPY ./tinycloud-sdk-rs/ ./tinycloud-sdk-rs/
COPY ./tinycloud-sdk-wasm/ ./tinycloud-sdk-wasm/
COPY ./siwe/ ./siwe/
COPY ./siwe-recap/ ./siwe-recap/
COPY ./cacao/ ./cacao/
COPY ./scripts/ ./scripts/
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/app/target \
    cargo chef cook --release --recipe-path recipe.json

COPY --from=planner /app/ ./
RUN chmod +x ./scripts/init-tinycloud-data.sh && ./scripts/init-tinycloud-data.sh
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/app/target \
    cargo build --release --bin tinycloud && \
    cp /app/target/release/tinycloud /app/tinycloud

RUN addgroup -g 1000 tinycloud && adduser -u 1000 -G tinycloud -s /bin/sh -D tinycloud

FROM scratch AS runtime
COPY --from=builder /etc/passwd /etc/passwd
COPY --from=builder /etc/group /etc/group
COPY --from=builder --chown=tinycloud:tinycloud /app/tinycloud /tinycloud
COPY --from=builder --chown=tinycloud:tinycloud /app/data ./data
COPY ./tinycloud.toml ./
USER tinycloud:tinycloud
ENV ROCKET_ADDRESS=0.0.0.0
EXPOSE 8000
EXPOSE 8001
EXPOSE 8081
ENTRYPOINT ["/tinycloud"]
LABEL org.opencontainers.image.source=https://github.com/TinyCloudLabs/tinycloud-node
