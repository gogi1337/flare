use std::collections::HashMap;
use std::sync::Arc;

use tokio_rustls::rustls::crypto::ring;
use tokio_rustls::rustls::pki_types::pem::PemObject;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::rustls::server::{ClientHello, ResolvesServerCert};
use tokio_rustls::rustls::sign::CertifiedKey;
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::TlsAcceptor;

use crate::config::Config;

/// Loads a PEM certificate chain and private key, and checks that they belong together.
pub fn load_certified_key(cert_path: &str, key_path: &str) -> Result<CertifiedKey, String> {
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(cert_path)
        .map_err(|e| format!("cert '{}': {}", cert_path, e))?
        .collect::<Result<_, _>>()
        .map_err(|e| format!("cert '{}': {}", cert_path, e))?;

    if certs.is_empty() {
        return Err(format!("cert '{}': no certificates found", cert_path));
    }

    let key =
        PrivateKeyDer::from_pem_file(key_path).map_err(|e| format!("key '{}': {}", key_path, e))?;

    CertifiedKey::from_der(certs, key, &ring::default_provider())
        .map_err(|e| format!("cert '{}' with key '{}': {}", cert_path, key_path, e))
}

/// Picks the route's own certificate when the client's SNI name matches a route that has
/// one, and falls back to the default `tls.cert` otherwise (including clients without SNI).
#[derive(Debug)]
struct SniResolver {
    default: Arc<CertifiedKey>,
    by_name: HashMap<String, Arc<CertifiedKey>>,
}

impl ResolvesServerCert for SniResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let by_sni = client_hello
            .server_name()
            .and_then(|name| self.by_name.get(&name.to_ascii_lowercase()));
        Some(Arc::clone(by_sni.unwrap_or(&self.default)))
    }
}

pub fn build_acceptor(conf: &Config) -> Result<TlsAcceptor, String> {
    let tls = conf.tls.as_ref().ok_or("no `tls` section in config")?;

    let default = Arc::new(load_certified_key(&tls.cert, &tls.key)?);

    let mut by_name = HashMap::new();
    for route in &conf.routes {
        if let (Some(cert), Some(key)) = (&route.cert, &route.key) {
            let certified = load_certified_key(cert, key)
                .map_err(|e| format!("route '{}': {}", route.route, e))?;
            by_name.insert(route.route.clone(), Arc::new(certified));
        }
    }

    let mut server_config = ServerConfig::builder_with_provider(Arc::new(ring::default_provider()))
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("tls setup: {}", e))?
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(SniResolver { default, by_name }));

    // only http/1.1 ;( @todo
    server_config.alpn_protocols = vec![b"http/1.1".to_vec()];

    Ok(TlsAcceptor::from(Arc::new(server_config)))
}

/// Test helper: writes a fresh self-signed cert for `name` and returns
/// (cert_path, key_path, cert_der).
#[cfg(test)]
pub(crate) fn write_test_cert(name: &str) -> (String, String, CertificateDer<'static>) {
    use std::sync::atomic::{AtomicUsize, Ordering};
    static COUNTER: AtomicUsize = AtomicUsize::new(0);

    let dir = std::env::temp_dir().join(format!(
        "flare-test-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).unwrap();

    let generated = rcgen::generate_simple_self_signed(vec![name.to_string()]).unwrap();
    let cert_path = dir.join("cert.pem");
    let key_path = dir.join("key.pem");
    std::fs::write(&cert_path, generated.cert.pem()).unwrap();
    std::fs::write(&key_path, generated.signing_key.serialize_pem()).unwrap();

    (
        cert_path.to_string_lossy().into_owned(),
        key_path.to_string_lossy().into_owned(),
        generated.cert.der().clone(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loads_matching_cert_and_key() {
        let (cert, key, der) = write_test_cert("a.local");
        let loaded = load_certified_key(&cert, &key).unwrap();
        assert_eq!(loaded.cert[0], der);
    }

    #[test]
    fn rejects_key_from_another_cert() {
        let (cert_a, _, _) = write_test_cert("a.local");
        let (_, key_b, _) = write_test_cert("b.local");
        assert!(load_certified_key(&cert_a, &key_b).is_err());
    }

    #[test]
    fn rejects_missing_files() {
        let (cert, key, _) = write_test_cert("a.local");
        let err = load_certified_key("/nonexistent/cert.pem", &key).unwrap_err();
        assert!(err.contains("/nonexistent/cert.pem"), "{}", err);
        let err = load_certified_key(&cert, "/nonexistent/key.pem").unwrap_err();
        assert!(err.contains("/nonexistent/key.pem"), "{}", err);
    }

    #[test]
    fn rejects_file_without_certificates() {
        let (_, key, _) = write_test_cert("a.local");
        // A key file is valid PEM but contains no CERTIFICATE blocks
        let err = load_certified_key(&key, &key).unwrap_err();
        assert!(err.contains("no certificates"), "{}", err);
    }

    #[test]
    fn build_acceptor_fails_on_bad_route_cert() {
        let (cert, key, _) = write_test_cert("a.local");
        let yaml = format!(
            "addr: 127.0.0.1:80\ndisable_domain_not_configured_warns: true\ndisable_failed_to_reach_warns: true\n\
             tls:\n  addr: 127.0.0.1:443\n  cert: {}\n  key: {}\n\
             routes:\n  - route: b.local\n    forward: http://127.0.0.1:1\n    cert: /nonexistent.pem\n    key: {}\n",
            cert, key, key
        );
        let conf = Config::from_yaml(&yaml).unwrap();
        let err = build_acceptor(&conf).err().unwrap();
        assert!(err.contains("b.local"), "{}", err);
    }
}
