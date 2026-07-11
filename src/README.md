# ws-deflate-sidecar

A terminating WebSocket reverse proxy that adds RFC 7692 `permessage-deflate` compression in front of an upstream server that does not support compression.

```text
browser/client <-- WebSocket + permessage-deflate --> sidecar <-- plain WebSocket --> upstream
```

The sidecar preserves:

- The exact WebSocket path configured by `--proxy`
- Query parameters from each client connection
- Text and binary message boundaries
- Cookies, authorization, origin, and other end-to-end request headers
- The subprotocol actually selected by the upstream server

Ping/pong frames terminate at each side of the proxy. Close frames are propagated when a close reason is available.

## Run

For the existing server at `http://localhost:52771/ws/`:

```bash
cargo run --release -- \
  --proxy http://localhost:52771/ws/ \
  --listen 52772
```

Clients then connect to:

```text
ws://YOUR_HOST:52772/ws/
```

When running the sidecar in Docker, `localhost` is the container itself. On Linux, use `--network host`, or point `--proxy` at a host-reachable address.

Browsers normally offer `permessage-deflate` automatically. When negotiated, the response opening handshake includes a `Sec-WebSocket-Extensions: permessage-deflate...` header.

Useful options:

```text
--bind 0.0.0.0
--max-message-size 67108864
--handshake-timeout-seconds 10
```

Set logs with `RUST_LOG`, for example:

```bash
RUST_LOG=debug cargo run --release -- \
  --proxy http://localhost:52771/ws/ \
  --listen 52772
```

## Build

```bash
cargo build --release
./target/release/ws-deflate-sidecar \
  --proxy http://localhost:52771/ws/ \
  --listen 52772
```

## Reverse proxy in front

If TLS is terminated by Caddy, nginx, HAProxy, or a cloud load balancer, route `/ws/` to the sidecar rather than directly to port `52771`. The sidecar itself currently accepts `http://` or `ws://` upstream URLs; this is intentional for a localhost sidecar deployment.

Example nginx upstream target:

```nginx
location /ws/ {
    proxy_pass http://127.0.0.1:52772;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Host $host;
}
```

Do not configure nginx WebSocket compression separately. The sidecar performs the RFC 7692 negotiation and frame compression.

## Verify compression

With a client that exposes response headers, confirm that the sidecar's `101 Switching Protocols` response contains:

```text
Sec-WebSocket-Extensions: permessage-deflate
```

Chrome/Chromium DevTools also shows the extension in the WebSocket opening-handshake response headers.

## Behavior and limits

- Only the path in `--proxy` is served. Other paths return `404`.
- The upstream remains uncompressed by design.
- Compression helps repeated, textual, JSON, protobuf-like, and other compressible payloads. Already-compressed media may become slightly larger or consume CPU without meaningful bandwidth savings.
- `permessage-deflate` is message compression, not ordinary HTTP `Content-Encoding: deflate`.
