FROM clux/muslrust:stable AS chef
USER root
RUN cargo install cargo-chef
RUN rustup target add x86_64-unknown-linux-musl
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
COPY ./ucan-capabilities/ ./ucan-capabilities/
COPY ./cacao/ ./cacao/
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --target x86_64-unknown-linux-musl --recipe-path recipe.json
COPY --from=planner /app/ ./
RUN cargo build --release --target x86_64-unknown-linux-musl --bin tinycloud

FROM alpine AS runtime
RUN addgroup -S tinycloud && adduser -S tinycloud -G tinycloud
COPY --from=builder /app/target/x86_64-unknown-linux-musl/release/tinycloud /usr/local/bin/tinycloud
USER tinycloud
COPY ./tinycloud.toml ./
ENV ROCKET_ADDRESS=0.0.0.0
EXPOSE 8000
EXPOSE 8001
EXPOSE 8081
CMD ["tinycloud"]
LABEL org.opencontainers.image.source=https://github.com/TinyCloudLabs/tinycloud-node
