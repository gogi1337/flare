use std::{fs, net::SocketAddr};

use hyper::Uri;
use serde::Deserialize;

#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    pub addr: SocketAddr,
    pub disable_domain_not_configured_warns: bool,
    pub disable_failed_to_reach_warns: bool,
    /// Max seconds to wait for an upstream to send response headers before replying 504
    #[serde(default = "default_upstream_timeout")]
    pub upstream_timeout_secs: u64,
    /// Max seconds a client has to send its request headers before the connection is closed
    #[serde(default = "default_header_read_timeout")]
    pub header_read_timeout_secs: u64,
    pub routes: Vec<Route>,
}

fn default_upstream_timeout() -> u64 {
    30
}

fn default_header_read_timeout() -> u64 {
    10
}

impl Config {
    pub fn new(path: &str) -> Result<Config, Box<dyn std::error::Error>> {
        let content = fs::read_to_string(path)?;
        Config::from_yaml(&content)
    }

    pub fn from_yaml(content: &str) -> Result<Config, Box<dyn std::error::Error>> {
        let mut config: Config = serde_yaml::from_str(content)?;

        if config.upstream_timeout_secs == 0 || config.header_read_timeout_secs == 0 {
            return Err(
                "upstream_timeout_secs and header_read_timeout_secs must be greater than 0".into(),
            );
        }

        // Validate and normalize routes up front so bad config fails at startup,
        // not on the first request
        for route in &mut config.routes {
            route.route = route.route.to_ascii_lowercase();
            route.forward = route.forward.trim_end_matches('/').to_string();

            let uri: Uri = route.forward.parse().map_err(|e| {
                format!(
                    "route '{}': invalid forward '{}': {}",
                    route.route, route.forward, e
                )
            })?;

            if uri.scheme().is_none() || uri.authority().is_none() {
                return Err(format!(
                    "route '{}': forward '{}' must include scheme and host, e.g. http://127.0.0.1:3000",
                    route.route, route.forward
                ).into());
            }

            // The upstream client is plain HTTP only; https:// would pass parsing but fail on every request
            if uri.scheme_str() != Some("http") {
                return Err(format!(
                    "route '{}': forward '{}' must use http:// (https upstreams are not supported yet)",
                    route.route, route.forward
                ).into());
            }
        }

        Ok(config)
    }

    /// Finds a route by the request's Host header, ignoring port and case.
    pub fn find_route(&self, host: &str) -> Option<&Route> {
        let hostname = strip_port(host);
        self.routes
            .iter()
            .find(|route| route.route.eq_ignore_ascii_case(hostname))
    }
}

/// "example.com:8080" -> "example.com", "[::1]:8080" -> "[::1]"
fn strip_port(host: &str) -> &str {
    if host.starts_with('[') {
        match host.find(']') {
            Some(end) => &host[..=end],
            None => host,
        }
    } else {
        host.split(':').next().unwrap_or(host)
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct Route {
    pub route: String,
    pub forward: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn yaml(addr: &str, routes: &[(&str, &str)]) -> String {
        let mut s = format!(
            "addr: {}\ndisable_domain_not_configured_warns: true\ndisable_failed_to_reach_warns: true\nroutes:\n",
            addr
        );
        for (route, forward) in routes {
            s.push_str(&format!(
                "  - route: \"{}\"\n    forward: \"{}\"\n",
                route, forward
            ));
        }
        s
    }

    #[test]
    fn strip_port_handles_all_host_forms() {
        assert_eq!(strip_port("example.com"), "example.com");
        assert_eq!(strip_port("example.com:8080"), "example.com");
        assert_eq!(strip_port("127.0.0.1:80"), "127.0.0.1");
        assert_eq!(strip_port("[::1]"), "[::1]");
        assert_eq!(strip_port("[::1]:8080"), "[::1]");
        assert_eq!(strip_port("[broken"), "[broken");
        assert_eq!(strip_port(""), "");
    }

    #[test]
    fn parses_ipv4_and_ipv6_addr() {
        let c = Config::from_yaml(&yaml("0.0.0.0:80", &[])).unwrap();
        assert_eq!(c.addr, "0.0.0.0:80".parse().unwrap());

        let c = Config::from_yaml(&yaml("\"[::]:8080\"", &[])).unwrap();
        assert_eq!(c.addr, "[::]:8080".parse().unwrap());
    }

    #[test]
    fn rejects_invalid_addr() {
        assert!(Config::from_yaml(&yaml("localhost", &[])).is_err());
        assert!(Config::from_yaml(&yaml("0.0.0.0:99999", &[])).is_err());
    }

    #[test]
    fn rejects_forward_without_scheme() {
        let err = Config::from_yaml(&yaml("0.0.0.0:80", &[("a.com", "127.0.0.1:3000")]))
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("a.com"),
            "error should name the route: {}",
            err
        );
    }

    #[test]
    fn rejects_unparseable_forward() {
        assert!(Config::from_yaml(&yaml("0.0.0.0:80", &[("a.com", "http://bad host")])).is_err());
    }

    #[test]
    fn rejects_non_http_forward() {
        for forward in ["https://127.0.0.1:3000", "ftp://127.0.0.1:21"] {
            let err = Config::from_yaml(&yaml("0.0.0.0:80", &[("a.com", forward)]))
                .unwrap_err()
                .to_string();
            assert!(err.contains("http://"), "{}: {}", forward, err);
        }
    }

    #[test]
    fn timeouts_default_when_omitted() {
        let c = Config::from_yaml(&yaml("0.0.0.0:80", &[])).unwrap();
        assert_eq!(c.upstream_timeout_secs, 30);
        assert_eq!(c.header_read_timeout_secs, 10);
    }

    #[test]
    fn timeouts_can_be_set_and_must_be_positive() {
        let base = yaml("0.0.0.0:80", &[]);

        let c = Config::from_yaml(&format!(
            "{}upstream_timeout_secs: 5\nheader_read_timeout_secs: 2\n",
            base
        ))
        .unwrap();
        assert_eq!(c.upstream_timeout_secs, 5);
        assert_eq!(c.header_read_timeout_secs, 2);

        assert!(Config::from_yaml(&format!("{}upstream_timeout_secs: 0\n", base)).is_err());
        assert!(Config::from_yaml(&format!("{}header_read_timeout_secs: 0\n", base)).is_err());
    }

    #[test]
    fn normalizes_routes() {
        let c = Config::from_yaml(&yaml(
            "0.0.0.0:80",
            &[("App.Example.COM", "http://127.0.0.1:3000//")],
        ))
        .unwrap();
        assert_eq!(c.routes[0].route, "app.example.com");
        assert_eq!(c.routes[0].forward, "http://127.0.0.1:3000");
    }

    #[test]
    fn find_route_ignores_port_and_case() {
        let c = Config::from_yaml(&yaml(
            "0.0.0.0:80",
            &[
                ("a.com", "http://127.0.0.1:1"),
                ("b.com", "http://127.0.0.1:2"),
            ],
        ))
        .unwrap();

        assert_eq!(c.find_route("a.com").unwrap().forward, "http://127.0.0.1:1");
        assert_eq!(
            c.find_route("B.COM:8080").unwrap().forward,
            "http://127.0.0.1:2"
        );
        assert!(c.find_route("c.com").is_none());
        assert!(c.find_route("a.com.evil.net").is_none());
        assert!(c.find_route("").is_none());
    }

    #[test]
    fn example_config_is_valid() {
        let content = include_str!("../config.yaml.example");
        let c = Config::from_yaml(content).unwrap();
        assert!(!c.routes.is_empty());
    }
}
