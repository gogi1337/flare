#[macro_use]
extern crate log;

use config::Config;
use hyper::client::HttpConnector;
use hyper::header::{HeaderMap, HeaderName, HeaderValue, CONNECTION, LOCATION};
use hyper::http::StatusCode;
use hyper::server::conn::{AddrStream, Http};
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Client, Request, Response, Server, Uri};
use simple_logger::SimpleLogger;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

pub mod config;
pub mod tls;

type HttpClient = Client<HttpConnector, Body>;

/// Which listener a request came in on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Scheme {
    Http,
    Https,
}

impl Scheme {
    fn as_str(self) -> &'static str {
        match self {
            Scheme::Http => "http",
            Scheme::Https => "https",
        }
    }
}

// Headers that only apply to a single connection and must not be forwarded (RFC 9110 §7.6.1)
const HOP_BY_HOP: [&str; 8] = [
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

fn strip_hop_by_hop(headers: &mut HeaderMap) {
    // Headers named in Connection are also hop-by-hop
    let listed: Vec<HeaderName> = headers
        .get_all(CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .filter_map(|name| HeaderName::from_bytes(name.trim().as_bytes()).ok())
        .collect();

    for name in listed {
        headers.remove(name);
    }
    for name in HOP_BY_HOP {
        headers.remove(name);
    }
}

const X_FORWARDED_FOR: &str = "x-forwarded-for";
const X_FORWARDED_PROTO: &str = "x-forwarded-proto";
const X_FORWARDED_HOST: &str = "x-forwarded-host";

/// Tells the upstream who the real client is. X-Forwarded-For is appended to (so an
/// existing proxy chain is kept); the right-most entry is the one Flare vouches for.
fn add_forwarded_headers(
    headers: &mut HeaderMap,
    client_addr: SocketAddr,
    host: HeaderValue,
    scheme: Scheme,
) {
    let client_ip = client_addr.ip().to_string();
    let xff = match headers.get(X_FORWARDED_FOR).and_then(|v| v.to_str().ok()) {
        Some(existing) if !existing.trim().is_empty() => format!("{}, {}", existing, client_ip),
        _ => client_ip,
    };

    if let Ok(xff) = HeaderValue::from_str(&xff) {
        headers.insert(X_FORWARDED_FOR, xff);
    }
    headers.insert(X_FORWARDED_PROTO, HeaderValue::from_static(scheme.as_str()));
    headers.insert(X_FORWARDED_HOST, host);
}

/// 308 to the same host and path on the HTTPS listener. Only called for hosts that matched
/// a configured route, so the Location can't point somewhere arbitrary.
fn https_redirect(host: &str, https_port: u16, path_and_query: &str) -> Response<Body> {
    let hostname = config::strip_port(host);
    let location = if https_port == 443 {
        format!("https://{}{}", hostname, path_and_query)
    } else {
        format!("https://{}:{}{}", hostname, https_port, path_and_query)
    };

    match HeaderValue::from_str(&location) {
        Ok(location) => {
            let mut res = error_response(StatusCode::PERMANENT_REDIRECT, "Redirecting to HTTPS");
            res.headers_mut().insert(LOCATION, location);
            res
        }
        Err(_) => error_response(StatusCode::BAD_REQUEST, "Invalid Host header"),
    }
}

fn error_response(status: StatusCode, msg: &'static str) -> Response<Body> {
    let mut res = Response::new(Body::from(msg));
    *res.status_mut() = status;
    res
}

async fn handle_request(
    mut req: Request<Body>,
    conf: Arc<Config>,
    client: HttpClient,
    client_addr: SocketAddr,
    scheme: Scheme,
) -> Result<Response<Body>, Infallible> {
    // "Host" header determines where to reroute
    let host_value = match req.headers().get("host") {
        Some(value) => value.clone(),
        None => {
            return Ok(error_response(
                StatusCode::BAD_REQUEST,
                "Host header missing",
            ))
        }
    };
    let host = match host_value.to_str() {
        Ok(host) => host,
        Err(_) => {
            return Ok(error_response(
                StatusCode::BAD_REQUEST,
                "Invalid Host header",
            ))
        }
    };

    let route = match conf.find_route(host) {
        Some(route) => route,
        None => {
            if !conf.disable_domain_not_configured_warns {
                warn!("{} (Domain not configured)", host);
            }
            return Ok(error_response(
                StatusCode::NOT_FOUND,
                "Domain not configured",
            ));
        }
    };

    let path_and_query = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");

    if scheme == Scheme::Http {
        if let Some(tls) = conf.tls.as_ref().filter(|tls| tls.redirect_http) {
            return Ok(https_redirect(host, tls.addr.port(), path_and_query));
        }
    }

    let target_uri: Uri = match format!("{}{}", route.forward, path_and_query).parse() {
        Ok(uri) => uri,
        Err(e) => {
            warn!(
                "{} -> {} (Invalid target URI: {})",
                route.route, route.forward, e
            );
            return Ok(error_response(
                StatusCode::BAD_GATEWAY,
                "Failed to proxy request",
            ));
        }
    };

    *req.uri_mut() = target_uri;
    strip_hop_by_hop(req.headers_mut());
    add_forwarded_headers(req.headers_mut(), client_addr, host_value.clone(), scheme);

    // Bounds the wait for response headers only; streaming the body afterwards is not limited
    let timeout = Duration::from_secs(conf.upstream_timeout_secs);

    match tokio::time::timeout(timeout, client.request(req)).await {
        Ok(Ok(mut response)) => {
            strip_hop_by_hop(response.headers_mut());
            debug!("{} -> {}", route.route, route.forward);
            Ok(response)
        }
        Ok(Err(e)) => {
            if !conf.disable_failed_to_reach_warns {
                warn!(
                    "{} -> {} (Failed to reach: {})",
                    route.route, route.forward, e
                );
            }
            Ok(error_response(
                StatusCode::BAD_GATEWAY,
                "Failed to proxy request",
            ))
        }
        Err(_) => {
            if !conf.disable_failed_to_reach_warns {
                warn!(
                    "{} -> {} (Timed out after {}s)",
                    route.route, route.forward, conf.upstream_timeout_secs
                );
            }
            Ok(error_response(
                StatusCode::GATEWAY_TIMEOUT,
                "Upstream timed out",
            ))
        }
    }
}

/// Accepts TCP connections, does the TLS handshake, then serves HTTP/1.1 over it.
/// Each connection runs in its own task so a slow handshake never blocks others.
async fn serve_tls(
    listener: TcpListener,
    acceptor: TlsAcceptor,
    conf: Arc<Config>,
    client: HttpClient,
) {
    let header_read_timeout = Duration::from_secs(conf.header_read_timeout_secs);
    let mut http = Http::new();
    http.http1_only(true)
        .http1_header_read_timeout(header_read_timeout);

    loop {
        let (tcp, client_addr) = match listener.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                // e.g. out of file descriptors; back off instead of spinning
                warn!("HTTPS accept failed: {}", e);
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };

        let acceptor = acceptor.clone();
        let conf = Arc::clone(&conf);
        let client = client.clone();
        let http = http.clone();

        tokio::spawn(async move {
            // Bound the handshake too, so stalled clients can't pile up connections
            let tls_stream =
                match tokio::time::timeout(header_read_timeout, acceptor.accept(tcp)).await {
                    Ok(Ok(stream)) => stream,
                    Ok(Err(e)) => {
                        debug!("TLS handshake with {} failed: {}", client_addr, e);
                        return;
                    }
                    Err(_) => {
                        debug!("TLS handshake with {} timed out", client_addr);
                        return;
                    }
                };

            let service = service_fn(move |req| {
                handle_request(
                    req,
                    Arc::clone(&conf),
                    client.clone(),
                    client_addr,
                    Scheme::Https,
                )
            });

            if let Err(e) = http.serve_connection(tls_stream, service).await {
                debug!("HTTPS connection from {} ended: {}", client_addr, e);
            }
        });
    }
}

#[tokio::main]
async fn main() {
    SimpleLogger::new()
        .with_level(log::LevelFilter::Info)
        .init()
        .unwrap();

    let config = match Config::new("./config.yaml") {
        Ok(config) => Arc::new(config),
        Err(e) => {
            error!("Failed to load config: {}", e);
            std::process::exit(1);
        }
    };

    let addr = config.addr;
    // One client for the whole server so upstream connections are pooled and reused
    let client: HttpClient = Client::new();

    let header_read_timeout = Duration::from_secs(config.header_read_timeout_secs);

    // Load certificates and bind 443 before anything starts, so a bad cert or a taken port
    // fails loudly at startup instead of leaving a half-running proxy
    let https = match &config.tls {
        Some(tls) => {
            let acceptor = match tls::build_acceptor(&config) {
                Ok(acceptor) => acceptor,
                Err(e) => {
                    error!("Failed to load TLS certificates: {}", e);
                    std::process::exit(1);
                }
            };
            let listener = match TcpListener::bind(tls.addr).await {
                Ok(listener) => listener,
                Err(e) => {
                    error!("Failed to bind {}: {}", tls.addr, e);
                    std::process::exit(1);
                }
            };
            Some((listener, acceptor))
        }
        None => None,
    };

    let http_config = Arc::clone(&config);
    let http_client = client.clone();
    let make_svc = make_service_fn(move |conn: &AddrStream| {
        let config = Arc::clone(&http_config);
        let client = http_client.clone();
        let client_addr = conn.remote_addr();
        async move {
            Ok::<_, Infallible>(service_fn(move |req| {
                handle_request(
                    req,
                    Arc::clone(&config),
                    client.clone(),
                    client_addr,
                    Scheme::Http,
                )
            }))
        }
    });

    let server = match Server::try_bind(&addr) {
        // Closes connections that dribble in headers too slowly (slowloris)
        Ok(builder) => builder
            .http1_header_read_timeout(header_read_timeout)
            .serve(make_svc),
        Err(e) => {
            error!("Failed to bind {}: {}", addr, e);
            std::process::exit(1);
        }
    };

    info!("Flare HTTP running on {}", addr);

    let http = async {
        if let Err(e) = server.await {
            error!("HTTP server error: {}", e);
        }
    };

    match https {
        Some((listener, acceptor)) => {
            if let Some(tls) = &config.tls {
                info!("Flare HTTPS running on {}", tls.addr);
                if tls.redirect_http {
                    info!("Plain HTTP requests are redirected to HTTPS");
                }
            }
            tokio::select! {
                _ = http => {}
                _ = serve_tls(listener, acceptor, Arc::clone(&config), client) => {}
            }
        }
        None => http.await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::body::to_bytes;
    use std::net::SocketAddr;

    /// Upstream that echoes "METHOD path?query", reports which interesting request
    /// headers it received, and sends back a hop-by-hop header of its own.
    async fn spawn_upstream() -> SocketAddr {
        let make_svc = make_service_fn(|_conn| async {
            Ok::<_, Infallible>(service_fn(|req: Request<Body>| async move {
                let seen = |name: &str| req.headers().contains_key(name).to_string();
                let echo = |name: &str| {
                    req.headers()
                        .get(name)
                        .cloned()
                        .unwrap_or_else(|| HeaderValue::from_static(""))
                };
                let res = Response::builder()
                    .header("x-seen-xff", echo(X_FORWARDED_FOR))
                    .header("x-seen-xfp", echo(X_FORWARDED_PROTO))
                    .header("x-seen-xfh", echo(X_FORWARDED_HOST))
                    .header("x-seen-keep-alive", seen("keep-alive"))
                    .header("x-seen-secret", seen("x-secret"))
                    .header("x-seen-custom", seen("x-custom"))
                    .header("x-seen-host", req.headers().get("host").cloned().unwrap())
                    .header("keep-alive", "timeout=5")
                    .header("x-upstream", "1")
                    .body(Body::from(format!(
                        "{} {}",
                        req.method(),
                        req.uri().path_and_query().unwrap()
                    )))
                    .unwrap();
                Ok::<_, Infallible>(res)
            }))
        });

        let server = Server::bind(&"127.0.0.1:0".parse().unwrap()).serve(make_svc);
        let addr = server.local_addr();
        tokio::spawn(server);
        addr
    }

    /// A port with nothing listening on it.
    fn dead_port() -> u16 {
        std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }

    /// An upstream that accepts connections but never answers.
    async fn spawn_silent_upstream() -> SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((sock, _)) = listener.accept().await {
                held.push(sock);
            }
        });
        addr
    }

    fn config(routes: &[(&str, String)]) -> Arc<Config> {
        config_extra("", routes)
    }

    fn config_extra(extra: &str, routes: &[(&str, String)]) -> Arc<Config> {
        let mut s = format!(
            "addr: 127.0.0.1:0\ndisable_domain_not_configured_warns: true\ndisable_failed_to_reach_warns: true\n{}routes:\n",
            extra
        );
        for (route, forward) in routes {
            s.push_str(&format!(
                "  - route: \"{}\"\n    forward: \"{}\"\n",
                route, forward
            ));
        }
        Arc::new(Config::from_yaml(&s).unwrap())
    }

    const CLIENT: &str = "203.0.113.7:51234";

    async fn send(conf: &Arc<Config>, req: Request<Body>) -> (StatusCode, HeaderMap, String) {
        send_as(conf, req, Scheme::Http).await
    }

    async fn send_as(
        conf: &Arc<Config>,
        req: Request<Body>,
        scheme: Scheme,
    ) -> (StatusCode, HeaderMap, String) {
        let res = handle_request(
            req,
            Arc::clone(conf),
            Client::new(),
            CLIENT.parse().unwrap(),
            scheme,
        )
        .await
        .unwrap();
        read_response(res).await
    }

    async fn read_response(res: Response<Body>) -> (StatusCode, HeaderMap, String) {
        let status = res.status();
        let headers = res.headers().clone();
        let body = to_bytes(res.into_body()).await.unwrap();
        (status, headers, String::from_utf8(body.to_vec()).unwrap())
    }

    fn get(host: &str, path: &str) -> Request<Body> {
        Request::get(path)
            .header("host", host)
            .body(Body::empty())
            .unwrap()
    }

    #[test]
    fn strips_static_hop_by_hop_headers() {
        let mut h = HeaderMap::new();
        for name in HOP_BY_HOP {
            h.insert(name, "x".parse().unwrap());
        }
        h.insert("content-type", "text/plain".parse().unwrap());

        strip_hop_by_hop(&mut h);

        assert_eq!(h.len(), 1);
        assert!(h.contains_key("content-type"));
    }

    #[test]
    fn strips_headers_listed_in_connection() {
        let mut h = HeaderMap::new();
        h.insert("connection", "x-a, X-B ,keep-alive".parse().unwrap());
        h.append("connection", "x-c".parse().unwrap());
        h.insert("x-a", "1".parse().unwrap());
        h.insert("x-b", "1".parse().unwrap());
        h.insert("x-c", "1".parse().unwrap());
        h.insert("x-keep", "1".parse().unwrap());

        strip_hop_by_hop(&mut h);

        assert_eq!(h.len(), 1);
        assert!(h.contains_key("x-keep"));
    }

    #[tokio::test]
    async fn proxies_method_path_and_query() {
        let up = spawn_upstream().await;
        let conf = config(&[("app.local", format!("http://{}", up))]);

        let req = Request::post("/a/b?x=1&y=2")
            .header("host", "app.local")
            .body(Body::from("payload"))
            .unwrap();
        let (status, headers, body) = send(&conf, req).await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "POST /a/b?x=1&y=2");
        assert_eq!(headers["x-upstream"], "1");
    }

    #[tokio::test]
    async fn forwards_original_host_header() {
        let up = spawn_upstream().await;
        let conf = config(&[("app.local", format!("http://{}", up))]);

        let (_, headers, _) = send(&conf, get("App.Local:8080", "/")).await;
        assert_eq!(headers["x-seen-host"], "App.Local:8080");
    }

    #[tokio::test]
    async fn matches_host_with_port_and_any_case() {
        let up = spawn_upstream().await;
        let conf = config(&[("app.local", format!("http://{}", up))]);

        for host in ["app.local", "app.local:18080", "APP.Local", "APP.LOCAL:80"] {
            let (status, _, _) = send(&conf, get(host, "/")).await;
            assert_eq!(status, StatusCode::OK, "host {:?}", host);
        }
    }

    #[tokio::test]
    async fn routes_to_the_right_upstream() {
        let a = spawn_upstream().await;
        let b = spawn_upstream().await;
        let conf = config(&[
            ("a.local", format!("http://{}", a)),
            ("b.local", format!("http://{}/", b)),
        ]);

        let (_, _, body) = send(&conf, get("a.local", "/from-a")).await;
        assert_eq!(body, "GET /from-a");
        // trailing slash on forward must not produce "//from-b"
        let (_, _, body) = send(&conf, get("b.local", "/from-b")).await;
        assert_eq!(body, "GET /from-b");
    }

    #[tokio::test]
    async fn strips_hop_by_hop_both_directions() {
        let up = spawn_upstream().await;
        let conf = config(&[("app.local", format!("http://{}", up))]);

        let req = Request::get("/")
            .header("host", "app.local")
            .header("connection", "x-secret")
            .header("keep-alive", "timeout=5")
            .header("x-secret", "1")
            .header("x-custom", "1")
            .body(Body::empty())
            .unwrap();
        let (status, headers, _) = send(&conf, req).await;

        assert_eq!(status, StatusCode::OK);
        // request side, as seen by upstream
        assert_eq!(headers["x-seen-keep-alive"], "false");
        assert_eq!(headers["x-seen-secret"], "false");
        assert_eq!(headers["x-seen-custom"], "true");
        // response side
        assert!(!headers.contains_key("keep-alive"));
        assert_eq!(headers["x-upstream"], "1");
    }

    #[tokio::test]
    async fn adds_forwarded_headers() {
        let up = spawn_upstream().await;
        let conf = config(&[("app.local", format!("http://{}", up))]);

        let (_, headers, _) = send(&conf, get("App.Local:8080", "/")).await;
        assert_eq!(headers["x-seen-xff"], "203.0.113.7");
        assert_eq!(headers["x-seen-xfp"], "http");
        assert_eq!(headers["x-seen-xfh"], "App.Local:8080");
    }

    #[tokio::test]
    async fn appends_to_existing_x_forwarded_for() {
        let up = spawn_upstream().await;
        let conf = config(&[("app.local", format!("http://{}", up))]);

        let req = Request::get("/")
            .header("host", "app.local")
            .header("x-forwarded-for", "10.0.0.1")
            .header("x-forwarded-proto", "https") // spoofed, must be overwritten
            .header("x-forwarded-host", "evil.example") // spoofed, must be overwritten
            .body(Body::empty())
            .unwrap();
        let (_, headers, _) = send(&conf, req).await;

        assert_eq!(headers["x-seen-xff"], "10.0.0.1, 203.0.113.7");
        assert_eq!(headers["x-seen-xfp"], "http");
        assert_eq!(headers["x-seen-xfh"], "app.local");
    }

    #[test]
    fn forwarded_for_uses_bare_ipv6() {
        let mut h = HeaderMap::new();
        add_forwarded_headers(
            &mut h,
            "[2001:db8::1]:443".parse().unwrap(),
            HeaderValue::from_static("a.com"),
            Scheme::Http,
        );
        assert_eq!(h[X_FORWARDED_FOR], "2001:db8::1");
    }

    // ---- HTTPS ----

    /// `tls:` section pointing at a fresh default cert for `default_name`. The tls.addr is a
    /// placeholder: tests bind their own listener and only the port is used for redirects.
    fn tls_section(default_name: &str, tls_port: u16, redirect: bool) -> String {
        let (cert, key, _) = tls::write_test_cert(default_name);
        format!(
            "tls:\n  addr: 127.0.0.1:{}\n  cert: {}\n  key: {}\n  redirect_http: {}\n",
            tls_port, cert, key, redirect
        )
    }

    #[tokio::test]
    async fn redirects_http_to_https_when_enabled() {
        let conf = config_extra(
            &tls_section("app.local", 443, true),
            &[("app.local", "http://127.0.0.1:1".into())],
        );

        let (status, headers, _) = send(&conf, get("App.Local:80", "/a/b?x=1")).await;
        assert_eq!(status, StatusCode::PERMANENT_REDIRECT);
        assert_eq!(headers[LOCATION], "https://App.Local/a/b?x=1");
    }

    #[tokio::test]
    async fn redirect_keeps_non_default_https_port() {
        let conf = config_extra(
            &tls_section("app.local", 8443, true),
            &[("app.local", "http://127.0.0.1:1".into())],
        );

        let (_, headers, _) = send(&conf, get("app.local:8080", "/")).await;
        assert_eq!(headers[LOCATION], "https://app.local:8443/");
    }

    #[tokio::test]
    async fn no_redirect_for_unknown_domain_or_when_disabled() {
        let up = spawn_upstream().await;

        let conf = config_extra(
            &tls_section("app.local", 443, true),
            &[("app.local", format!("http://{}", up))],
        );
        let (status, _, _) = send(&conf, get("other.local", "/")).await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        let conf = config_extra(
            &tls_section("app.local", 443, false),
            &[("app.local", format!("http://{}", up))],
        );
        let (status, headers, _) = send(&conf, get("app.local", "/")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(headers["x-seen-xfp"], "http");
    }

    #[tokio::test]
    async fn https_requests_are_proxied_not_redirected() {
        let up = spawn_upstream().await;
        let conf = config_extra(
            &tls_section("app.local", 443, true),
            &[("app.local", format!("http://{}", up))],
        );

        let (status, headers, body) = send_as(&conf, get("app.local", "/x"), Scheme::Https).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "GET /x");
        assert_eq!(headers["x-seen-xfp"], "https");
    }

    /// Starts `serve_tls` on a random port and returns its address.
    async fn spawn_tls_proxy(conf: Arc<Config>) -> SocketAddr {
        let acceptor = tls::build_acceptor(&conf).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(serve_tls(listener, acceptor, conf, Client::new()));
        addr
    }

    /// Connects over TLS with SNI `sni`, trusting only `trusted`, and sends GET / with
    /// Host `sni`. Fails if the server's certificate isn't valid for `sni`.
    async fn https_get(
        proxy: SocketAddr,
        sni: &str,
        trusted: &[tokio_rustls::rustls::pki_types::CertificateDer<'static>],
    ) -> Result<(StatusCode, HeaderMap, String), String> {
        use tokio_rustls::rustls::{self, pki_types::ServerName};

        let mut roots = rustls::RootCertStore::empty();
        for cert in trusted {
            roots.add(cert.clone()).unwrap();
        }
        let client_config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
        let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));

        let tcp = tokio::net::TcpStream::connect(proxy).await.unwrap();
        let name = ServerName::try_from(sni.to_string()).unwrap();
        let tls = connector
            .connect(name, tcp)
            .await
            .map_err(|e| e.to_string())?;

        let (mut sender, conn) = hyper::client::conn::handshake(tls).await.unwrap();
        tokio::spawn(conn);
        let res = sender.send_request(get(sni, "/")).await.unwrap();
        Ok(read_response(res).await)
    }

    #[tokio::test]
    async fn serves_https_end_to_end() {
        let up = spawn_upstream().await;
        let (cert, key, der) = tls::write_test_cert("app.local");
        let conf = config_extra(
            &format!(
                "tls:\n  addr: 127.0.0.1:1\n  cert: {}\n  key: {}\n",
                cert, key
            ),
            &[("app.local", format!("http://{}", up))],
        );
        let proxy = spawn_tls_proxy(conf).await;

        let (status, headers, body) = https_get(proxy, "app.local", &[der]).await.unwrap();
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "GET /");
        assert_eq!(headers["x-seen-xfp"], "https");
        assert_eq!(headers["x-seen-xff"], "127.0.0.1");
    }

    #[tokio::test]
    async fn picks_certificate_by_sni() {
        let up = spawn_upstream().await;
        let (default_cert, default_key, default_der) = tls::write_test_cert("a.local");
        let (b_cert, b_key, b_der) = tls::write_test_cert("b.local");

        let yaml = format!(
            "addr: 127.0.0.1:0\ndisable_domain_not_configured_warns: true\ndisable_failed_to_reach_warns: true\n\
             tls:\n  addr: 127.0.0.1:1\n  cert: {}\n  key: {}\n\
             routes:\n\
             \x20 - route: a.local\n    forward: http://{up}\n\
             \x20 - route: b.local\n    forward: http://{up}\n    cert: {}\n    key: {}\n\
             \x20 - route: c.local\n    forward: http://{up}\n",
            default_cert, default_key, b_cert, b_key, up = up
        );
        let proxy = spawn_tls_proxy(Arc::new(Config::from_yaml(&yaml).unwrap())).await;
        let trusted = [default_der, b_der];

        // The client only accepts a cert valid for the name it asked for, so a successful
        // handshake proves the right certificate was chosen
        assert!(https_get(proxy, "a.local", &trusted).await.is_ok());
        assert!(https_get(proxy, "b.local", &trusted).await.is_ok());

        // c.local has no cert of its own: it gets the default (a.local) cert, which the
        // client rejects because the name doesn't match
        let err = https_get(proxy, "c.local", &trusted).await.unwrap_err();
        assert!(err.to_lowercase().contains("name"), "{}", err);
    }

    #[tokio::test]
    async fn rejects_untrusted_and_plain_http_on_tls_port() {
        let (cert, key, _) = tls::write_test_cert("app.local");
        let conf = config_extra(
            &format!(
                "tls:\n  addr: 127.0.0.1:1\n  cert: {}\n  key: {}\n",
                cert, key
            ),
            &[("app.local", "http://127.0.0.1:1".into())],
        );
        let proxy = spawn_tls_proxy(conf).await;

        // A client that doesn't trust the cert must fail the handshake
        let (_, _, other) = tls::write_test_cert("app.local");
        assert!(https_get(proxy, "app.local", &[other]).await.is_err());

        // Plain HTTP to the TLS port gets no HTTP response; the proxy keeps running after
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut tcp = tokio::net::TcpStream::connect(proxy).await.unwrap();
        tcp.write_all(b"GET / HTTP/1.1\r\nHost: app.local\r\n\r\n")
            .await
            .unwrap();
        let mut buf = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(2), tcp.read_to_end(&mut buf)).await;
        assert!(!buf.starts_with(b"HTTP/"));

        assert!(tokio::net::TcpStream::connect(proxy).await.is_ok());
    }

    #[tokio::test]
    async fn slow_upstream_is_504() {
        let up = spawn_silent_upstream().await;
        let conf = config_extra(
            "upstream_timeout_secs: 1\n",
            &[("app.local", format!("http://{}", up))],
        );

        let started = std::time::Instant::now();
        let (status, _, body) = send(&conf, get("app.local", "/")).await;

        assert_eq!(status, StatusCode::GATEWAY_TIMEOUT);
        assert_eq!(body, "Upstream timed out");
        assert!(started.elapsed() < Duration::from_secs(3));
    }

    #[tokio::test]
    async fn non_text_host_is_400() {
        let conf = config(&[]);
        let req = Request::get("/")
            .header("host", HeaderValue::from_bytes(b"caf\xe9.local").unwrap())
            .body(Body::empty())
            .unwrap();
        let (status, _, _) = send(&conf, req).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn unknown_domain_is_404() {
        let conf = config(&[("app.local", "http://127.0.0.1:1".into())]);
        let (status, _, body) = send(&conf, get("other.local", "/")).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(body, "Domain not configured");
    }

    #[tokio::test]
    async fn missing_host_is_400() {
        let conf = config(&[]);
        let req = Request::get("/").body(Body::empty()).unwrap();
        let (status, _, body) = send(&conf, req).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body, "Host header missing");
    }

    #[tokio::test]
    async fn unreachable_upstream_is_502() {
        let conf = config(&[("app.local", format!("http://127.0.0.1:{}", dead_port()))]);
        let (status, _, body) = send(&conf, get("app.local", "/")).await;
        assert_eq!(status, StatusCode::BAD_GATEWAY);
        assert_eq!(body, "Failed to proxy request");
    }
}
