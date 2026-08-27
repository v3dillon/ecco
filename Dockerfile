# Relay image. Build in this repo:
#   docker build -t ghcr.io/v3dillon/ecco-relay:latest .
FROM rust:1-alpine AS build
RUN apk add --no-cache build-base openssl-dev
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release

FROM alpine:3
RUN apk add --no-cache ca-certificates libgcc
COPY --from=build /src/target/release/ecco /usr/local/bin/ecco
VOLUME /data
EXPOSE 4200
ENTRYPOINT ["ecco", "relay", "--port", "4200", "--data", "/data"]
