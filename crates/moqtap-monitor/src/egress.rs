//! How uploads reach ingest: directly, or through an HTTP `CONNECT` tunnel,
//! with server certificates checked by the platform's verifier.

use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::{Request, Response, Uri};
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use hyper_util::client::legacy::connect::proxy::Tunnel;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::client::proxy::matcher::{Intercept, Matcher};
use hyper_util::rt::TokioExecutor;
use rustls::crypto::CryptoProvider;
use rustls_platform_verifier::Verifier;
use tower_service::Service;

use crate::Error;

/// How uploads reach the ingest endpoint.
#[derive(Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum Proxy {
    /// For an `https` endpoint, the proxy in `HTTPS_PROXY` (or
    /// `https_proxy`), unless `NO_PROXY` (or `no_proxy`) names the
    /// endpoint's host. The default.
    #[default]
    FromEnv,
    /// Connect directly, whatever the environment says.
    Direct,
    /// Tunnel through this proxy, whatever the environment says: an
    /// `http://` or `https://` URL, with optional `user:password@`.
    Url(String),
}

impl std::fmt::Debug for Proxy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Proxy::FromEnv => f.write_str("FromEnv"),
            Proxy::Direct => f.write_str("Direct"),
            Proxy::Url(_) => f.write_str("Url(<redacted>)"),
        }
    }
}

/// The proxy to tunnel through to `endpoint` (`scheme://host[:port]`), if any.
pub(crate) fn route(
    endpoint: &str,
    proxy: &Proxy,
    env: impl Fn(&str) -> Option<String>,
) -> Result<Option<Intercept>, Error> {
    let dst: Uri = endpoint.parse().map_err(|_| Error::InvalidEndpoint)?;
    match proxy {
        Proxy::Direct => Ok(None),
        Proxy::Url(url) => {
            let found = Matcher::builder().all(url.as_str()).build().intercept(&dst);
            found.and_then(tunnelable).map(Some).ok_or(Error::InvalidProxy)
        }
        Proxy::FromEnv => {
            if dst.scheme_str() != Some("https") {
                return Ok(None);
            }
            let Some(url) = first(&env, &["HTTPS_PROXY", "https_proxy"]) else {
                return Ok(None);
            };
            let no = first(&env, &["NO_PROXY", "no_proxy"]).unwrap_or_default();
            let matched =
                |no: &str| Matcher::builder().https(url.as_str()).no(no).build().intercept(&dst);
            match matched(&no) {
                Some(found) => tunnelable(found).map(Some).ok_or(Error::InvalidProxy),
                // Bypassed by NO_PROXY, or a proxy URL that does not parse.
                None if matched("").is_some() => Ok(None),
                None => Err(Error::InvalidProxy),
            }
        }
    }
}

fn first(env: &impl Fn(&str) -> Option<String>, names: &[&str]) -> Option<String> {
    names.iter().find_map(|n| env(n).filter(|v| !v.trim().is_empty()))
}

/// Only HTTP proxies: the matcher also yields `socks*` ones.
fn tunnelable(found: Intercept) -> Option<Intercept> {
    matches!(found.uri().scheme_str(), Some("http" | "https")).then_some(found)
}

type Https = HttpsConnector<HttpConnector>;
type Tunneled = HttpsConnector<WithPort<Tunnel<Https>>>;

pub(crate) enum HttpClient {
    Direct(Client<Https, Full<Bytes>>),
    Tunnel(Box<Client<Tunneled, Full<Bytes>>>),
}

impl HttpClient {
    pub(crate) async fn request(
        &self,
        req: Request<Full<Bytes>>,
    ) -> Result<Response<Incoming>, hyper_util::client::legacy::Error> {
        match self {
            HttpClient::Direct(c) => c.request(req).await,
            HttpClient::Tunnel(c) => c.request(req).await,
        }
    }
}

/// A client that reaches ingest through `proxy`, or directly. The request
/// with the key goes only inside the tunnel; the proxy sees the `CONNECT`.
/// With `roots`, certificates are checked against those roots alone.
pub(crate) fn client(
    proxy: Option<Intercept>,
    roots: Option<&[Vec<u8>]>,
) -> Result<HttpClient, rustls::Error> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = rustls::ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_safe_default_protocol_versions()?;
    let tls = match roots {
        Some(roots) => {
            let mut store = rustls::RootCertStore::empty();
            for der in roots {
                store
                    .add(der.clone().into())
                    .map_err(|e| rustls::Error::General(format!("test root: {e}")))?;
            }
            builder.with_root_certificates(store).with_no_client_auth()
        }
        None => builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(verifier(provider)?))
            .with_no_client_auth(),
    };
    Ok(with_tls(proxy, tls))
}

/// The platform's verifier. Where it reads a CA store from files (Linux and
/// the BSDs), a host without one gets Mozilla's roots instead.
fn verifier(provider: Arc<CryptoProvider>) -> Result<Verifier, rustls::Error> {
    match Verifier::new(Arc::clone(&provider)) {
        #[cfg(all(unix, not(target_os = "android"), not(target_vendor = "apple")))]
        Err(_) => Verifier::new_with_extra_roots(
            webpki_root_certs::TLS_SERVER_ROOT_CERTS.iter().cloned(),
            provider,
        ),
        found => found,
    }
}

fn with_tls(proxy: Option<Intercept>, tls: rustls::ClientConfig) -> HttpClient {
    let https =
        || HttpsConnectorBuilder::new().with_tls_config(tls.clone()).https_or_http().enable_http1();
    let builder = Client::builder(TokioExecutor::new());
    match proxy {
        None => HttpClient::Direct(builder.build(https().build())),
        Some(p) => {
            let mut tunnel = Tunnel::new(p.uri().clone(), https().build());
            if let Some(auth) = p.basic_auth() {
                tunnel = tunnel.with_auth(auth.clone());
            }
            HttpClient::Tunnel(Box::new(builder.build(https().wrap_connector(WithPort(tunnel)))))
        }
    }
}

/// Names the scheme's default port, which `Tunnel` would otherwise take as
/// 443 for an `http` destination too.
#[derive(Clone)]
pub(crate) struct WithPort<C>(C);

impl<C: Service<Uri>> Service<Uri> for WithPort<C> {
    type Response = C::Response;
    type Error = C::Error;
    type Future = C::Future;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), C::Error>> {
        self.0.poll_ready(cx)
    }

    fn call(&mut self, dst: Uri) -> C::Future {
        self.0.call(with_port(dst))
    }
}

fn with_port(dst: Uri) -> Uri {
    let (Some(host), None) = (dst.host(), dst.port()) else { return dst };
    let port = if dst.scheme_str() == Some("http") { 80 } else { 443 };
    let mut parts = dst.clone().into_parts();
    parts.authority = format!("{host}:{port}").parse().ok();
    Uri::from_parts(parts).unwrap_or(dst)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env<'a>(vars: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |name| vars.iter().find(|(k, _)| *k == name).map(|(_, v)| v.to_string())
    }

    fn via(endpoint: &str, proxy: &Proxy, vars: &[(&str, &str)]) -> Option<String> {
        route(endpoint, proxy, env(vars)).expect("route").map(|i| i.uri().to_string())
    }

    const E: &str = "https://moqgest.com";

    #[test]
    fn https_proxy_in_either_case() {
        assert_eq!(via(E, &Proxy::FromEnv, &[]), None);
        let upper = [("HTTPS_PROXY", "http://proxy.corp:3128")];
        assert_eq!(via(E, &Proxy::FromEnv, &upper).as_deref(), Some("http://proxy.corp:3128/"));
        let lower = [("https_proxy", "proxy.corp:8080")];
        assert_eq!(via(E, &Proxy::FromEnv, &lower).as_deref(), Some("http://proxy.corp:8080/"));
        let both = [("HTTPS_PROXY", "http://a:1"), ("https_proxy", "http://b:2")];
        assert_eq!(via(E, &Proxy::FromEnv, &both).as_deref(), Some("http://a:1/"));
        let blank = [("HTTPS_PROXY", " "), ("https_proxy", "http://b:2")];
        assert_eq!(via(E, &Proxy::FromEnv, &blank).as_deref(), Some("http://b:2/"));
        let tls = [("HTTPS_PROXY", "https://proxy.corp")];
        assert_eq!(via(E, &Proxy::FromEnv, &tls).as_deref(), Some("https://proxy.corp/"));
    }

    #[test]
    fn no_proxy_in_either_case() {
        let p = ("HTTPS_PROXY", "http://proxy.corp:3128");
        for no in ["moqgest.com", ".moqgest.com", "a.example, moqgest.com", "*"] {
            assert_eq!(via(E, &Proxy::FromEnv, &[p, ("NO_PROXY", no)]), None, "{no}");
            assert_eq!(via(E, &Proxy::FromEnv, &[p, ("no_proxy", no)]), None, "{no}");
        }
        assert_eq!(
            via("https://eu.moqgest.com", &Proxy::FromEnv, &[p, ("no_proxy", "moqgest.com")]),
            None
        );
        for no in ["example.com", "gest.com", "10.0.0.0/8"] {
            assert!(via(E, &Proxy::FromEnv, &[p, ("NO_PROXY", no)]).is_some(), "{no}");
        }
        let ip = [p, ("NO_PROXY", "10.0.0.0/8")];
        assert_eq!(via("https://10.1.2.3:8443", &Proxy::FromEnv, &ip), None);
    }

    #[test]
    fn the_environment_proxies_only_https() {
        let vars = [
            ("HTTPS_PROXY", "http://p:1"),
            ("HTTP_PROXY", "http://p:2"),
            ("ALL_PROXY", "http://p:3"),
        ];
        assert_eq!(via("http://127.0.0.1:8787", &Proxy::FromEnv, &vars), None);
        assert_eq!(
            via(E, &Proxy::FromEnv, &[("HTTP_PROXY", "http://p:2"), ("ALL_PROXY", "http://p:3")]),
            None
        );
    }

    #[test]
    fn an_explicit_choice_overrides_the_environment() {
        let vars = [("HTTPS_PROXY", "http://env:1"), ("NO_PROXY", "*")];
        assert_eq!(via(E, &Proxy::Direct, &vars), None);
        let url = Proxy::Url("http://u:p@explicit:9".into());
        assert_eq!(via(E, &url, &vars).as_deref(), Some("http://explicit:9/"));
        assert_eq!(via("http://127.0.0.1:8787", &url, &[]).as_deref(), Some("http://explicit:9/"));
    }

    #[test]
    fn userinfo_becomes_basic_proxy_authorization() {
        let url = Proxy::Url("http://alice:s%3Acret@proxy:3128".into());
        let found = route(E, &url, env(&[])).unwrap().unwrap();
        // base64("alice:s:cret")
        assert_eq!(found.basic_auth().unwrap(), "Basic YWxpY2U6czpjcmV0");
        assert!(found.basic_auth().unwrap().is_sensitive());
        assert!(!found.uri().to_string().contains("alice"));
    }

    #[test]
    fn unusable_proxies_are_refused() {
        for bad in ["socks5://proxy:1080", "ftp://proxy", "", "http://"] {
            let r = route(E, &Proxy::Url(bad.into()), env(&[]));
            assert!(matches!(r, Err(Error::InvalidProxy)), "{bad}");
            let r = route(E, &Proxy::FromEnv, env(&[("HTTPS_PROXY", bad)]));
            if bad.is_empty() {
                assert!(matches!(r, Ok(None)));
            } else {
                assert!(matches!(r, Err(Error::InvalidProxy)), "{bad}");
            }
        }
        let bypassed = [("HTTPS_PROXY", "socks5://proxy:1080"), ("NO_PROXY", "moqgest.com")];
        assert!(matches!(route(E, &Proxy::FromEnv, env(&bypassed)), Ok(None)));
    }

    #[test]
    fn the_tunnel_names_the_default_port() {
        let p = |s: &str| with_port(s.parse().unwrap()).to_string();
        assert_eq!(p("https://moqgest.com/v1/source?i=x"), "https://moqgest.com:443/v1/source?i=x");
        assert_eq!(p("http://localhost/"), "http://localhost:80/");
        assert_eq!(p("http://[::1]:8787/"), "http://[::1]:8787/");
        assert_eq!(p("https://[::1]/"), "https://[::1]:443/");
    }

    #[test]
    fn the_platform_verifier_initialises() {
        assert!(client(None, None).is_ok());
        let found = route(E, &Proxy::Url("http://proxy:3128".into()), env(&[])).unwrap();
        assert!(client(found, None).is_ok());
        assert!(client(None, Some(&[b"not a certificate".to_vec()])).is_err());
    }

    #[tokio::test]
    async fn an_https_proxy_carries_an_https_upload() {
        use hyper_util::rt::TokioIo;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::{TcpListener, TcpStream};

        let ck = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_string()]).unwrap();
        let cert = ck.cert.der().clone();
        let key = rustls::pki_types::PrivatePkcs8KeyDer::from(ck.signing_key.serialize_der());
        let provider = || Arc::new(rustls::crypto::ring::default_provider());
        let server = rustls::ServerConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert.clone()], key.into())
            .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server));

        let ingest = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let ingest_addr = ingest.local_addr().unwrap();
        let tls = acceptor.clone();
        let (seen_tx, mut seen) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(async move {
            let (tcp, _) = ingest.accept().await.unwrap();
            let stream = tls.accept(tcp).await.unwrap();
            let svc = hyper::service::service_fn(move |req: Request<Incoming>| {
                let auth = req.headers().get("authorization").cloned();
                let _ = seen_tx.send(auth);
                async {
                    Ok::<_, std::convert::Infallible>(
                        Response::builder().status(204).body(Full::new(Bytes::new())).unwrap(),
                    )
                }
            });
            let conn = hyper::server::conn::http1::Builder::new();
            let _ = conn.serve_connection(TokioIo::new(stream), svc).await;
        });

        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let (head_tx, head_rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let (tcp, _) = proxy.accept().await.unwrap();
            let mut client = acceptor.accept(tcp).await.unwrap();
            let mut head = Vec::new();
            let mut byte = [0u8; 1];
            while !head.ends_with(b"\r\n\r\n") {
                client.read_exact(&mut byte).await.unwrap();
                head.push(byte[0]);
            }
            let head = String::from_utf8(head).unwrap();
            let target = head.split(' ').nth(1).unwrap().to_string();
            let _ = head_tx.send(head);
            client.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n").await.unwrap();
            let mut upstream = TcpStream::connect(target).await.unwrap();
            let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
        });

        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert).unwrap();
        let tls = rustls::ClientConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let endpoint = format!("https://{ingest_addr}");
        let via = Proxy::Url(format!("https://{proxy_addr}"));
        let found = route(&endpoint, &via, env(&[])).unwrap();
        assert_eq!(found.as_ref().unwrap().uri().scheme_str(), Some("https"));
        let req = Request::post(format!("{endpoint}/v1/source"))
            .header("authorization", "Bearer mqt_sk_inside")
            .body(Full::new(Bytes::from_static(b"body")))
            .unwrap();
        let resp = with_tls(found, tls).request(req).await.expect("request");
        assert_eq!(resp.status(), 204);

        let head = head_rx.await.unwrap();
        assert!(head.starts_with(&format!("CONNECT {ingest_addr} HTTP/1.1\r\n")), "{head}");
        assert!(!head.contains("mqt_sk_") && !head.contains("Bearer"), "{head}");
        let auth = seen.recv().await.unwrap().unwrap();
        assert_eq!(auth, "Bearer mqt_sk_inside");
    }
}
