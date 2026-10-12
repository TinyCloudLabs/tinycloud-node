FROM dstacktee/dstack-ingress:1.4@sha256:11c0481ca1e2ef9c959187ff3c01c7f59c26d631c7717a571ad994b96203bb0b

# nginx.conf includes conf.d/*.conf in http {}; 00 sorts before the generated server block.
COPY header-buffers.conf /etc/nginx/conf.d/00-header-buffers.conf
