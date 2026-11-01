# Sidecar image for the encrypted deletion-ledger backup loop (TC-887).
# Alpine keeps only the current package revision per release; if a pin below
# stops resolving, the build fails loudly. Bump the pins together with the base
# digest (Alpine 3.24.3 at this digest).
FROM alpine:3.24@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a
# /var/lib/tinycloud/ledger gets the node image's owner and mode: if this
# container is the first to mount a fresh `deletion-ledger` volume, Docker
# seeds the volume from here and the node can still write it.
RUN apk add --no-cache age=1.3.2-r1 curl=8.23.0-r0 \
    && addgroup -g 1000 tinycloud && adduser -u 1000 -G tinycloud -s /sbin/nologin -D -H tinycloud \
    && mkdir -p /var/lib/tinycloud/ledger && chown 1000:1000 /var/lib/tinycloud/ledger && chmod 700 /var/lib/tinycloud/ledger
COPY --chmod=0755 deploy/ledger-backup/ledger-backup.sh /usr/local/bin/ledger-backup.sh
USER 1000:1000
ENTRYPOINT ["/usr/local/bin/ledger-backup.sh"]
CMD []
LABEL org.opencontainers.image.source=https://github.com/TinyCloudLabs/tinycloud-node
