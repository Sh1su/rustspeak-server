# RustSpeak server (TeamSpeak 3 protocol) – multi-stage build
FROM rust:1-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY tsproto ./tsproto
COPY server ./server
RUN cargo build --release -p ts3-server --locked

FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates tini \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --home /data --uid 10001 rustspeak \
 && mkdir -p /data && chown rustspeak /data
COPY --from=build /src/target/release/ts3-server /usr/local/bin/ts3-server
USER rustspeak
WORKDIR /data
VOLUME ["/data"]
# 9987/udp voice · 9987/tcp video relay · 10011/tcp ServerQuery · 10013/tcp bot interface
EXPOSE 9987/udp 9987/tcp 10011/tcp 10013/tcp
ENTRYPOINT ["/usr/bin/tini", "--", "ts3-server", "--data", "/data/ts3server_state.json"]
