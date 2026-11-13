FROM dstacktee/dstack-ingress:1.4@sha256:11c0481ca1e2ef9c959187ff3c01c7f59c26d631c7717a571ad994b96203bb0b

# nginx.conf includes conf.d/*.conf in http {}; 00 sorts before the generated server block.
COPY header-buffers.conf /etc/nginx/conf.d/00-header-buffers.conf

# TC-970: the base nginx.conf writes every raw request line and the client IP
# to /var/log/nginx/access.log, and request errors to error.log. Those are
# regular files: the image has no logrotate binary or cron, so they grow until
# the disk fills. Drop both; redacted-logging.conf logs each request to stdout
# by route template instead. nginx still opens its compiled-in error.log while
# parsing the config (parse warnings land there), so that path points to
# stderr. The checks fail the build if the base image changes these lines.
COPY redacted-logging.conf /etc/nginx/conf.d/00-redacted-logging.conf
RUN sed -i \
        -e '/^[[:space:]]*access_log[[:space:]]/d' \
        -e 's#^error_log[[:space:]].*#error_log  /dev/stderr notice;#' \
        /etc/nginx/nginx.conf \
    && ! grep -q -e 'access_log' -e '/var/log/nginx' /etc/nginx/nginx.conf \
    && grep -q '^error_log  /dev/stderr notice;$' /etc/nginx/nginx.conf \
    && mkdir -p /var/log/nginx \
    && ln -sf /dev/stderr /var/log/nginx/error.log

# The base entrypoint generates the nginx server block with
# `ssl_ecdh_curve secp384r1;`, so X25519-first clients (browsers, curl, Bun)
# pay a HelloRetryRequest round trip on every new connection. Offer X25519 and
# P-256 first; P-384 stays allowed, so this is not a security downgrade. The
# checks fail the build if the base image changes this line.
RUN test "$(grep -cF 'ssl_ecdh_curve secp384r1;' /scripts/entrypoint.sh)" = 1 \
    && sed -i 's#ssl_ecdh_curve secp384r1;#ssl_ecdh_curve X25519:prime256v1:secp384r1;#' /scripts/entrypoint.sh \
    && test "$(grep -cF 'ssl_ecdh_curve X25519:prime256v1:secp384r1;' /scripts/entrypoint.sh)" = 1 \
    && ! grep -qF 'ssl_ecdh_curve secp384r1;' /scripts/entrypoint.sh
