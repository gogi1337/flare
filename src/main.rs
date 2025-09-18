#[macro_use]
extern crate log;

use config::Config;
use hyper::{Body, Client, Request, Response, Server};
use hyper::service::{make_service_fn, service_fn};
use hyper::http::StatusCode;
use simple_logger::SimpleLogger;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;

pub mod config;

async fn handle_request(req: Request<Body>, conf: Arc<Config>) -> Result<Response<Body>, Infallible> {
    // "Host" header determines where to reroute
    let host_header = req.headers().get("host").and_then(|value| value.to_str().ok());

    if let Some(host) = host_header {
        if let Some(ref route) = conf.find_route(host) {
            let uri = req.uri();
            let path_and_query = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");

            // Redirect to target server for the specified port
            let target_uri = format!("{}{}", route.forward, path_and_query);
            let target_uri: String = target_uri.parse().unwrap();

            let client = Client::new();
            let mut proxied_request = Request::builder()
                .method(req.method())
                .uri(target_uri);

            // Copy headers from the original request
            for (key, value) in req.headers().iter() {
                proxied_request = proxied_request.header(key, value);
            }

            let proxied_request = proxied_request.body(req.into_body()).unwrap();

            match client.request(proxied_request).await {
                Ok(response) => {
                    let mut builder = Response::builder()
                        .status(response.status());

                    // Copy headers from the proxied response
                    for (key, value) in response.headers().iter() {
                        builder = builder.header(key, value);
                    }

                    debug!("{} -> {}", route.route, route.forward);

                    Ok(builder.body(response.into_body()).unwrap())

                }
                Err(_) => {
                    if !conf.disable_failed_to_reach_warns {
                        warn!("{} -> {} (Failed to reach)", route.route, route.forward);
                    }
                    
                    Ok(Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(Body::from("Failed to proxy request"))
                    .unwrap())
                },
            }
        } else {
            if !conf.disable_domain_not_configured_warns {
                warn!("{} (Domain not configured)", host);
            }

            Ok(Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(Body::from("Domain not configured"))
                .unwrap())
        }
    } else {
        // Return 404 if the Host header is missing
        Ok(Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Body::from("Host header missing"))
            .unwrap())
    }
}

#[tokio::main]
async fn main() {
    SimpleLogger::new()
    .with_level(log::LevelFilter::Info)
    .init()
    .unwrap();

    let config = Config::new("./config.yaml").expect("Failed to load config");

    let addr = SocketAddr::from(config.host());
    let config = Arc::new(config);

    let make_svc = make_service_fn(move |_conn| {
        let config = Arc::clone(&config);
        async move {
            Ok::<_, Infallible>(service_fn(move |req| {
                handle_request(req, Arc::clone(&config))
            }))
        }
    });

    let server = Server::bind(&addr).serve(make_svc);

    info!("Flare running on {}", addr);

    if let Err(e) = server.await {
        eprintln!("Server error: {}", e);
    }
}
