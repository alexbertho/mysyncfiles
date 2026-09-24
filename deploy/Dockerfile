FROM rust:1.98-bookworm@sha256:93ce27a88655056a51dbdd8f5f2d7ddc071c7b0070fb288a37b5a285fc83971e AS build
RUN apt-get update && apt-get install -y --no-install-recommends libtss2-dev libssl-dev pkg-config \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY deploy/install.sh deploy/mysync.service ./deploy/
RUN cargo build --locked --release --bin mysync-server

FROM debian:13-slim@sha256:a99cfc517144bc59b1978475ec53b46ecabec7e43635402ee5b77cc54cd1b20a
RUN apt-get update && apt-get install -y --no-install-recommends tpm2-tools \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/target/release/mysync-server /usr/local/bin/mysync-server
USER 65532:65532
EXPOSE 8484
ENTRYPOINT ["/usr/local/bin/mysync-server"]
CMD ["serve", "--data-dir", "/data", "--listen", "0.0.0.0:8484", "--releases-dir", "/releases"]
