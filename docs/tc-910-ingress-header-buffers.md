# TC-910: dstack ingress request headers

The tee.node production ingress has nginx's default `large_client_header_buffers 4 8k`. Session activation (`POST /delegate`) places the signed delegation in one `Authorization` header; replication login headers can exceed 8 KiB and fail with `400 Request Header Or Cookie Too Large`.

`deploy/ingress/Dockerfile` wraps the pinned `dstacktee/dstack-ingress:1.4` image and copies `header-buffers.conf` to `/etc/nginx/conf.d/00-header-buffers.conf`. 1.20.1 shipped the wrapper on `dstack-ingress:20250924`; #261 moved it to `1.4`, which also honours `CLIENT_MAX_BODY_SIZE` (200 MB) and the proxy timeouts set in the compose. The directive `large_client_header_buffers 4 32k;` resides in the nginx `http {}` context. The prefixed filename is loaded before its generated `default.conf` server block. This raises the per-header-line capacity while retaining four buffers.

The upstream entrypoint's `setup_nginx_conf` generates `default.conf`; it does not remove the custom `00-header-buffers.conf` drop-in. The directive is valid in `http` context.

## Deploy and rollback

1. **Build:** dispatch `docker.yml` on the release ref, then record the ingress image digest from the job summary.
2. **Check the pull:** confirm the digest pulls anonymously. A new GHCR package may start private; make it public if it is.
3. **Pin and deploy:** set the literal digest in the `dstack-ingress` compose `image:` and deploy together with node 1.20.1.
4. **Verify:** send an `Authorization` header of about 12 KB to `https://tee.node.tinycloud.xyz/delegate`; confirm the request is not a 400 and the connection is not reset.
5. **Rollback:** revert the compose `image:` line to the previous wrapper digest and redeploy. That is `ghcr.io/tinycloudlabs/tinycloud-node-ingress@sha256:726c6d35858e50c5524cc97e789c2c8f09620e77d708bb71bdc9370e3d80ed3e`: the 1.20.1 wrapper on `20250924`, with 32 KB headers and the default body limit. To drop the wrapper entirely, use `dstacktee/dstack-ingress:20250924@sha256:40429d78060ef3066b5f93676bf3ba7c2e9ac47d4648440febfdda558aed4b32`. The `CLIENT_MAX_BODY_SIZE` and `PROXY_*_TIMEOUT` compose lines have no effect on `20250924`.

Tracked by [Linear TC-910](https://linear.app/tinycloud/issue/TC-910).
