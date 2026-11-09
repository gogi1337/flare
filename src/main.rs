#[macro_use]
extern crate log;

use config::Config;
use hyper::client::HttpConnector;
use hyper::header::{HeaderMap, HeaderName, HeaderValue, CONNECTION};
use hyper::http::StatusCode;
use hyper::server::conn::AddrStream;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Client, Request, Response, Server, Uri};
use simple_logger::SimpleLogger;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

pub mod config;

type HttpClient = Client<HttpConnector, Body>;

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
fn add_forwarded_headers(headers: &mut HeaderMap, client_addr: SocketAddr, host: HeaderValue) {
    let client_ip = client_addr.ip().to_string();
    let xff = match headers.get(X_FORWARDED_FOR).and_then(|v| v.to_str().ok()) {
        Some(existing) if !existing.trim().is_empty() => format!("{}, {}", existing, client_ip),
        _ => client_ip,
    };

    if let Ok(xff) = HeaderValue::from_str(&xff) {
        headers.insert(X_FORWARDED_FOR, xff);
    }
    headers.insert(X_FORWARDED_PROTO, HeaderValue::from_static("http"));
    headers.insert(X_FORWARDED_HOST, host);
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
    add_forwarded_headers(req.headers_mut(), client_addr, host_value.clone());

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

    let make_svc = make_service_fn(move |conn: &AddrStream| {
        let config = Arc::clone(&config);
        let client = client.clone();
        let client_addr = conn.remote_addr();
        async move {
            Ok::<_, Infallible>(service_fn(move |req| {
                handle_request(req, Arc::clone(&config), client.clone(), client_addr)
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

    info!("Flare running on {}", addr);

    if let Err(e) = server.await {
        error!("Server error: {}", e);
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
        let res = handle_request(
            req,
            Arc::clone(conf),
            Client::new(),
            CLIENT.parse().unwrap(),
        )
        .await
        .unwrap();
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
        );
        assert_eq!(h[X_FORWARDED_FOR], "2001:db8::1");
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
