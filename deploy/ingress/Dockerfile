FROM dstacktee/dstack-ingress:20250924@sha256:40429d78060ef3066b5f93676bf3ba7c2e9ac47d4648440febfdda558aed4b32

# nginx.conf includes conf.d/*.conf in http {}; 00 sorts before the generated server block.
COPY header-buffers.conf /etc/nginx/conf.d/00-header-buffers.conf
