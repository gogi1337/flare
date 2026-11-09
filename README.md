# Flare
Minimal reverse proxy written in Rust with Tokio, Hyper and rustls.

## Notice
- ⚠️ Not recommended to use in large-scale infrastructures.

## How to setup
- Remove `.example` from `config.yaml.example` and setup your routes
- Run the executable from the directory containing `config.yaml`

### If giving permission denied on port :80 or :443
- `sudo setcap 'CAP_NET_BIND_SERVICE+ep' ./flare`

## HTTPS
Add a `tls` section to `config.yaml`:

```yaml
tls:
  addr: 0.0.0.0:443
  cert: /etc/letsencrypt/live/example.com/fullchain.pem
  key: /etc/letsencrypt/live/example.com/privkey.pem
  redirect_http: true
```

- `cert` must be the full chain PEM (leaf certificate first), `key` its PEM private key.
  RSA, ECDSA and Ed25519 keys work.
- `addr` keeps serving plain HTTP. With `redirect_http: true`, requests for configured
  routes get a `308` to the same path on HTTPS.
- Several domains: use one certificate covering all of them, or give a route its own
  `cert`/`key`. The certificate is picked by the domain the client asks for (SNI); anything
  else gets the `tls` certificate.
- Certificates are loaded at startup: a missing file or a key that doesn't match its
  certificate stops Flare with an error. Restart Flare after renewing certificates.
- Flare does not obtain certificates itself. Use certbot or similar, e.g.
  `certbot certonly --standalone -d example.com` while Flare is stopped (it needs port 80).
- Upstreams always receive plain HTTP with `X-Forwarded-Proto: https` set.
- TLS 1.2 and 1.3 only; HTTP/1.1 only.
