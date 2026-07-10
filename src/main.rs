use std::{
    collections::HashSet,
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use anyhow::{anyhow, bail, Context as _, Result};
use bytes::{Bytes, BytesMut};
use clap::Parser;
use http::{
    header::{
        CONNECTION, SEC_WEBSOCKET_KEY, SEC_WEBSOCKET_PROTOCOL, SEC_WEBSOCKET_VERSION, UPGRADE,
    },
    HeaderMap, HeaderName, HeaderValue, Uri,
};
use ratchet::{
    accept_with,
    deflate::DeflateExtProvider,
    subscribe_with,
    Message,
    NoExtProvider,
    PayloadType,
    SubprotocolRegistry,
    TryIntoRequest,
    WebSocketConfig,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::{TcpListener, TcpStream},
    time::timeout,
};
use tracing::{debug, info, warn};
use tracing_subscriber::EnvFilter;
use url::Url;

const MAX_HANDSHAKE_BYTES: usize = 64 * 1024;

/// WebSocket reverse-proxy sidecar that adds RFC 7692 permessage-deflate.
#[derive(Debug, Parser)]
#[command(version, about)]
struct Args {
    /// Upstream WebSocket URL. http:// is treated as ws://.
    #[arg(long)]
    proxy: Url,

    /// TCP port on which the compressed WebSocket endpoint is exposed.
    #[arg(long)]
    listen: u16,

    /// Address on which to listen.
    #[arg(long, default_value_t = IpAddr::V4(Ipv4Addr::UNSPECIFIED))]
    bind: IpAddr,

    /// Maximum decompressed WebSocket message size in bytes.
    #[arg(long, default_value_t = 64 * 1024 * 1024)]
    max_message_size: usize,

    /// Timeout for downstream and upstream opening handshakes.
    #[arg(long, default_value_t = 10)]
    handshake_timeout_seconds: u64,
}

#[derive(Debug)]
struct AppConfig {
    upstream: Url,
    max_message_size: usize,
    handshake_timeout: Duration,
}

#[derive(Debug)]
struct HandshakeInfo {
    target: String,
    headers: HeaderMap,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let args = Args::parse();
    let upstream = normalize_upstream_url(args.proxy)?;
    let listen_addr = SocketAddr::new(args.bind, args.listen);
    let listener = TcpListener::bind(listen_addr)
        .await
        .with_context(|| format!("failed to bind {listen_addr}"))?;

    let config = Arc::new(AppConfig {
        upstream,
        max_message_size: args.max_message_size,
        handshake_timeout: Duration::from_secs(args.handshake_timeout_seconds),
    });

    info!(
        listen = %listen_addr,
        upstream = %config.upstream,
        path = %config.upstream.path(),
        "WebSocket DEFLATE sidecar started"
    );

    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, peer) = accepted.context("accept failed")?;
                let config = Arc::clone(&config);

                tokio::spawn(async move {
                    if let Err(err) = handle_connection(stream, peer, config).await {
                        warn!(%peer, error = %err, "connection ended with an error");
                    }
                });
            }
            signal = tokio::signal::ctrl_c() => {
                signal.context("failed to listen for Ctrl-C")?;
                info!("shutdown signal received");
                break;
            }
        }
    }

    Ok(())
}

fn normalize_upstream_url(mut url: Url) -> Result<Url> {
    match url.scheme() {
        "http" => url
            .set_scheme("ws")
            .map_err(|_| anyhow!("could not convert http:// URL to ws://"))?,
        "ws" => {}
        "https" | "wss" => {
            bail!("TLS upstreams are not supported by this build; use http:// or ws://")
        }
        other => bail!("unsupported upstream URL scheme: {other}"),
    }

    if url.host_str().is_none() {
        bail!("--proxy must contain a host");
    }

    if url.fragment().is_some() {
        bail!("--proxy must not contain a URL fragment");
    }

    Ok(url)
}

async fn handle_connection(
    mut downstream_tcp: TcpStream,
    peer: SocketAddr,
    config: Arc<AppConfig>,
) -> Result<()> {
    downstream_tcp
        .set_nodelay(true)
        .context("failed to set TCP_NODELAY on downstream socket")?;

    let handshake_bytes = match timeout(
        config.handshake_timeout,
        read_opening_handshake(&mut downstream_tcp),
    )
    .await
    {
        Ok(Ok(bytes)) => bytes,
        Ok(Err(err)) => {
            let _ = write_http_error(&mut downstream_tcp, 400, "Bad Request", &err.to_string()).await;
            return Err(err);
        }
        Err(_) => {
            let _ = write_http_error(
                &mut downstream_tcp,
                408,
                "Request Timeout",
                "WebSocket opening handshake timed out",
            )
            .await;
            bail!("downstream opening handshake timed out");
        }
    };

    let handshake = match parse_opening_handshake(&handshake_bytes) {
        Ok(handshake) => handshake,
        Err(err) => {
            let _ = write_http_error(&mut downstream_tcp, 400, "Bad Request", &err.to_string()).await;
            return Err(err);
        }
    };

    if !is_websocket_upgrade(&handshake.headers) {
        write_http_error(
            &mut downstream_tcp,
            426,
            "Upgrade Required",
            "This endpoint only accepts WebSocket upgrade requests",
        )
        .await?;
        return Ok(());
    }

    let incoming_uri: Uri = handshake
        .target
        .parse()
        .context("invalid request target in opening handshake")?;

    if incoming_uri.path() != config.upstream.path() {
        write_http_error(&mut downstream_tcp, 404, "Not Found", "WebSocket path not found").await?;
        return Ok(());
    }

    let client_subprotocols = extract_subprotocols(&handshake.headers)?;
    let upstream_url = upstream_url_for_request(&config.upstream, incoming_uri.query());

    let upstream_tcp = match timeout(
        config.handshake_timeout,
        connect_upstream(&upstream_url),
    )
    .await
    {
        Ok(Ok(stream)) => stream,
        Ok(Err(err)) => {
            let _ = write_http_error(
                &mut downstream_tcp,
                502,
                "Bad Gateway",
                "Could not connect to the upstream WebSocket",
            )
            .await;
            return Err(err);
        }
        Err(_) => {
            let _ = write_http_error(
                &mut downstream_tcp,
                504,
                "Gateway Timeout",
                "Upstream connection timed out",
            )
            .await;
            bail!("upstream TCP connection timed out");
        }
    };

    let mut upstream_request = upstream_url
        .as_str()
        .try_into_request()
        .context("failed to create upstream WebSocket request")?;
    copy_end_to_end_headers(&handshake.headers, upstream_request.headers_mut());

    let upstream_protocols = if client_subprotocols.is_empty() {
        SubprotocolRegistry::default()
    } else {
        SubprotocolRegistry::new(client_subprotocols.clone())
            .context("invalid Sec-WebSocket-Protocol request header")?
    };

    // The upstream explicitly gets NoExtProvider: it remains an uncompressed
    // WebSocket exactly like the existing service.
    let upstream = match timeout(
        config.handshake_timeout,
        subscribe_with(
            websocket_config(config.max_message_size),
            upstream_tcp,
            upstream_request,
            NoExtProvider,
            upstream_protocols,
        ),
    )
    .await
    {
        Ok(Ok(upgraded)) => upgraded,
        Ok(Err(err)) => {
            let _ = write_http_error(
                &mut downstream_tcp,
                502,
                "Bad Gateway",
                "Upstream rejected the WebSocket opening handshake",
            )
            .await;
            return Err(anyhow!(err)).context("upstream WebSocket handshake failed");
        }
        Err(_) => {
            let _ = write_http_error(
                &mut downstream_tcp,
                504,
                "Gateway Timeout",
                "Upstream WebSocket opening handshake timed out",
            )
            .await;
            bail!("upstream WebSocket handshake timed out");
        }
    };

    // Only advertise the subprotocol that the upstream actually selected.
    let downstream_protocols = match upstream.subprotocol.as_ref() {
        Some(protocol) => SubprotocolRegistry::new([protocol.clone()])
            .context("upstream returned an invalid subprotocol")?,
        None => SubprotocolRegistry::default(),
    };

    // Replay the already-read HTTP bytes to Ratchet. Ratchet performs the
    // authoritative RFC 6455 validation and negotiates RFC 7692 downstream.
    let downstream_stream = PrefixedStream::new(handshake_bytes.freeze(), downstream_tcp);
    let downstream_upgrader = timeout(
        config.handshake_timeout,
        accept_with(
            downstream_stream,
            websocket_config(config.max_message_size),
            DeflateExtProvider::default(),
            downstream_protocols,
        ),
    )
    .await
    .context("downstream WebSocket handshake timed out")??;

    let downstream = downstream_upgrader
        .upgrade()
        .await
        .context("failed to finish downstream WebSocket upgrade")?;

    debug!(
        %peer,
        upstream = %upstream_url,
        subprotocol = ?upstream.subprotocol,
        "WebSocket proxy connection established"
    );

    relay_bidirectionally(downstream.websocket, upstream.websocket)
        .await
        .with_context(|| format!("relay failure for {peer}"))?;

    debug!(%peer, "WebSocket proxy connection closed");
    Ok(())
}

fn websocket_config(max_message_size: usize) -> WebSocketConfig {
    let mut config = WebSocketConfig::default();
    config.max_message_size = max_message_size;
    config
}

async fn connect_upstream(url: &Url) -> Result<TcpStream> {
    let host = url.host_str().context("upstream URL has no host")?;
    let port = url
        .port_or_known_default()
        .context("upstream URL has no port and no known default")?;

    let stream = TcpStream::connect((host, port))
        .await
        .with_context(|| format!("failed to connect to upstream {host}:{port}"))?;
    stream
        .set_nodelay(true)
        .context("failed to set TCP_NODELAY on upstream socket")?;
    Ok(stream)
}

fn upstream_url_for_request(base: &Url, query: Option<&str>) -> Url {
    let mut result = base.clone();
    result.set_query(query.or(base.query()));
    result
}

async fn relay_bidirectionally<DS, DE, US, UE>(
    downstream: ratchet::WebSocket<DS, DE>,
    upstream: ratchet::WebSocket<US, UE>,
) -> Result<()>
where
    DS: ratchet::WebSocketStream + 'static,
    DE: ratchet::SplittableExtension + 'static,
    US: ratchet::WebSocketStream + 'static,
    UE: ratchet::SplittableExtension + 'static,
{
    let (mut downstream_sender, mut downstream_receiver) = downstream
        .split()
        .context("failed to split downstream WebSocket")?;
    let (mut upstream_sender, mut upstream_receiver) = upstream
        .split()
        .context("failed to split upstream WebSocket")?;

    let downstream_to_upstream = async {
        let mut buffer = BytesMut::new();
        loop {
            match downstream_receiver.read(&mut buffer).await? {
                Message::Text => {
                    upstream_sender.write(&buffer, PayloadType::Text).await?;
                    buffer.clear();
                }
                Message::Binary => {
                    upstream_sender.write(&buffer, PayloadType::Binary).await?;
                    buffer.clear();
                }
                Message::Ping(_) | Message::Pong(_) => {
                    // Ratchet answers pings locally. Control frames do not need
                    // to traverse a terminating reverse proxy.
                }
                Message::Close(reason) => {
                    if let Some(reason) = reason {
                        let _ = upstream_sender.close(reason).await;
                    }
                    return Ok::<(), ratchet::Error>(());
                }
            }
        }
    };

    let upstream_to_downstream = async {
        let mut buffer = BytesMut::new();
        loop {
            match upstream_receiver.read(&mut buffer).await? {
                Message::Text => {
                    // Ratchet automatically applies permessage-deflate here
                    // when it was negotiated with the downstream client.
                    downstream_sender.write(&buffer, PayloadType::Text).await?;
                    buffer.clear();
                }
                Message::Binary => {
                    downstream_sender.write(&buffer, PayloadType::Binary).await?;
                    buffer.clear();
                }
                Message::Ping(_) | Message::Pong(_) => {}
                Message::Close(reason) => {
                    if let Some(reason) = reason {
                        let _ = downstream_sender.close(reason).await;
                    }
                    return Ok::<(), ratchet::Error>(());
                }
            }
        }
    };

    // One completed direction means the session is over. Dropping the other
    // half closes the corresponding TCP stream and prevents a dead connection
    // from lingering forever.
    tokio::select! {
        result = downstream_to_upstream => result.context("downstream-to-upstream relay failed")?,
        result = upstream_to_downstream => result.context("upstream-to-downstream relay failed")?,
    }

    Ok(())
}

async fn read_opening_handshake(stream: &mut TcpStream) -> Result<BytesMut> {
    let mut bytes = BytesMut::with_capacity(4096);
    let mut chunk = [0_u8; 4096];

    loop {
        if find_header_end(&bytes).is_some() {
            return Ok(bytes);
        }

        if bytes.len() >= MAX_HANDSHAKE_BYTES {
            bail!("opening handshake exceeds {MAX_HANDSHAKE_BYTES} bytes");
        }

        let read = stream.read(&mut chunk).await.context("handshake read failed")?;
        if read == 0 {
            bail!("client disconnected before completing the opening handshake");
        }

        bytes.extend_from_slice(&chunk[..read]);
        if bytes.len() > MAX_HANDSHAKE_BYTES {
            bail!("opening handshake exceeds {MAX_HANDSHAKE_BYTES} bytes");
        }
    }
}

fn parse_opening_handshake(bytes: &[u8]) -> Result<HandshakeInfo> {
    let mut raw_headers = [httparse::EMPTY_HEADER; 128];
    let mut request = httparse::Request::new(&mut raw_headers);
    let status = request.parse(bytes).context("malformed HTTP request")?;

    if !status.is_complete() {
        bail!("incomplete HTTP opening handshake");
    }

    if request.method != Some("GET") {
        bail!("WebSocket opening handshake must use GET");
    }

    if request.version != Some(1) {
        bail!("WebSocket opening handshake must use HTTP/1.1");
    }

    let target = request
        .path
        .context("opening handshake has no request target")?
        .to_owned();

    let mut headers = HeaderMap::new();
    for raw in request.headers.iter() {
        let name = HeaderName::from_bytes(raw.name.as_bytes())
            .with_context(|| format!("invalid HTTP header name: {}", raw.name))?;
        let value = HeaderValue::from_bytes(raw.value)
            .with_context(|| format!("invalid value for HTTP header {name}"))?;
        headers.append(name, value);
    }

    Ok(HandshakeInfo { target, headers })
}

fn find_header_end(bytes: &[u8]) -> Option<usize> {
    bytes.windows(4).position(|window| window == b"\r\n\r\n")
}

fn is_websocket_upgrade(headers: &HeaderMap) -> bool {
    header_contains_token(headers, &CONNECTION, "upgrade")
        && header_contains_token(headers, &UPGRADE, "websocket")
        && headers.contains_key(SEC_WEBSOCKET_KEY)
        && headers
            .get(SEC_WEBSOCKET_VERSION)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.trim() == "13")
}

fn header_contains_token(headers: &HeaderMap, name: &HeaderName, expected: &str) -> bool {
    headers.get_all(name).iter().any(|value| {
        value.to_str().ok().is_some_and(|text| {
            text.split(',')
                .any(|token| token.trim().eq_ignore_ascii_case(expected))
        })
    })
}

fn extract_subprotocols(headers: &HeaderMap) -> Result<Vec<String>> {
    let mut protocols = Vec::new();

    for value in headers.get_all(SEC_WEBSOCKET_PROTOCOL).iter() {
        let value = value
            .to_str()
            .context("Sec-WebSocket-Protocol is not valid ASCII")?;
        protocols.extend(
            value
                .split(',')
                .map(str::trim)
                .filter(|protocol| !protocol.is_empty())
                .map(ToOwned::to_owned),
        );
    }

    Ok(protocols)
}

fn copy_end_to_end_headers(source: &HeaderMap, destination: &mut HeaderMap) {
    let connection_named_headers = connection_named_headers(source);

    for (name, value) in source.iter() {
        if should_forward_header(name, &connection_named_headers) {
            destination.append(name.clone(), value.clone());
        }
    }
}

fn connection_named_headers(headers: &HeaderMap) -> HashSet<String> {
    headers
        .get_all(CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(str::to_ascii_lowercase)
        .collect()
}

fn should_forward_header(name: &HeaderName, connection_named: &HashSet<String>) -> bool {
    if connection_named.contains(name.as_str()) {
        return false;
    }

    !matches!(
        name.as_str(),
        "connection"
            | "upgrade"
            | "host"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "proxy-connection"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "content-length"
            | "sec-websocket-key"
            | "sec-websocket-version"
            | "sec-websocket-extensions"
            | "sec-websocket-protocol"
    )
}

async fn write_http_error(
    stream: &mut TcpStream,
    status: u16,
    reason: &str,
    body: &str,
) -> io::Result<()> {
    let response = format!(
        "HTTP/1.1 {status} {reason}\r\n\
         Connection: close\r\n\
         Content-Type: text/plain; charset=utf-8\r\n\
         Content-Length: {}\r\n\
         \r\n\
         {}",
        body.len(),
        body
    );
    stream.write_all(response.as_bytes()).await?;
    stream.shutdown().await
}

/// Async stream that first replays bytes already consumed by the HTTP pre-parser.
#[derive(Debug)]
struct PrefixedStream<S> {
    prefix: Bytes,
    offset: usize,
    inner: S,
}

impl<S> PrefixedStream<S> {
    fn new(prefix: Bytes, inner: S) -> Self {
        Self {
            prefix,
            offset: 0,
            inner,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for PrefixedStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.offset < self.prefix.len() && buffer.remaining() > 0 {
            let remaining_prefix = &self.prefix[self.offset..];
            let length = remaining_prefix.len().min(buffer.remaining());
            buffer.put_slice(&remaining_prefix[..length]);
            self.offset += length;
            return Poll::Ready(Ok(()));
        }

        Pin::new(&mut self.inner).poll_read(cx, buffer)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PrefixedStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buffer)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_header_terminator() {
        assert_eq!(find_header_end(b"GET / HTTP/1.1\r\n\r\n"), Some(14));
        assert_eq!(find_header_end(b"GET / HTTP/1.1\r\n"), None);
    }

    #[test]
    fn extracts_multiple_subprotocols() {
        let mut headers = HeaderMap::new();
        headers.append(
            SEC_WEBSOCKET_PROTOCOL,
            HeaderValue::from_static("graphql-ws, chat"),
        );
        headers.append(
            SEC_WEBSOCKET_PROTOCOL,
            HeaderValue::from_static("json"),
        );

        assert_eq!(
            extract_subprotocols(&headers).unwrap(),
            vec!["graphql-ws", "chat", "json"]
        );
    }

    #[test]
    fn preserves_request_query_for_upstream() {
        let base = Url::parse("ws://localhost:52771/ws/").unwrap();
        let result = upstream_url_for_request(&base, Some("token=abc"));
        assert_eq!(result.as_str(), "ws://localhost:52771/ws/?token=abc");
    }
}
