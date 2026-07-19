# Build
FROM rust:1-slim AS build
WORKDIR /app
COPY Cargo.toml ./
COPY src ./src
RUN cargo build --release

# Runtime
FROM debian:stable-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /app/target/release/causal-seal-gateway /usr/local/bin/causal-seal-gateway
ENV CAUSAL_LISTEN=0.0.0.0:8080
EXPOSE 8080
ENTRYPOINT ["causal-seal-gateway"]
