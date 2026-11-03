//! Uploads through a local HTTP `CONNECT` proxy.

mod common;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use common::{read_body, Mock};
use http_body_util::{BodyExt, Full};
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use moqtap_monitor::{Delivery, Error, Monitor, Proxy, Sent};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const SOURCE: &str = "enc-test-1";
const KEY: &str = "mqt_sk_AAAAtestkeybody_testmac";

/// Answers each `CONNECT` with `status`, then relays bytes both ways. Keeps
/// the request heads it read.
struct ConnectProxy {
    url: String,
    heads: Arc<Mutex<Vec<String>>>,
}

impl ConnectProxy {
    async fn start(status: &'static str, userinfo: &str) -> ConnectProxy {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let url = format!("http://{userinfo}{}", listener.local_addr().expect("addr"));
        let heads = Arc::new(Mutex::new(Vec::new()));
        let h = Arc::clone(&heads);
        tokio::spawn(async move {
            loop {
                let Ok((mut client, _)) = listener.accept().await else { return };
                let h = Arc::clone(&h);
                tokio::spawn(async move {
                    let mut head = Vec::new();
                    let mut byte = [0u8; 1];
                    while !head.ends_with(b"\r\n\r\n") {
                        if client.read(&mut byte).await.unwrap_or(0) == 0 {
                            return;
                        }
                        head.push(byte[0]);
                    }
                    let head = String::from_utf8_lossy(&head).into_owned();
                    h.lock().unwrap().push(head.clone());
                    let reply = format!("HTTP/1.1 {status}\r\n\r\n");
                    if client.write_all(reply.as_bytes()).await.is_err()
                        || !status.starts_with("200")
                    {
                        return;
                    }
                    let target = head.split(' ').nth(1).unwrap_or_default().to_string();
                    let Ok(mut upstream) = TcpStream::connect(target).await else { return };
                    let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
                });
            }
        });
        ConnectProxy { url, heads }
    }

    fn heads(&self) -> Vec<String> {
        self.heads.lock().unwrap().clone()
    }
}

fn builder(mock: &Mock, proxy: Proxy) -> moqtap_monitor::MonitorBuilder {
    Monitor::builder(SOURCE, KEY)
        .endpoint(mock.endpoint())
        .proxy(proxy)
        .test_timing(Duration::from_millis(150), Duration::from_millis(20))
}

fn sent() -> Sent {
    Sent {
        group: 0,
        delivery: Delivery::Subgroup(0),
        object: 0,
        size: 100,
        starts_group: true,
        opens_subgroup: true,
        ends_group: false,
    }
}

#[tokio::test]
async fn uploads_go_through_the_tunnel_and_the_key_stays_inside_it() {
    let mock = Mock::start().await;
    let proxy = ConnectProxy::start("200 Connection established", "alice:s%3Acret@").await;
    let m = builder(&mock, Proxy::Url(proxy.url.clone())).start().expect("start");
    let relay = m.connection("https://relay.example.net/moq").expect("conn");
    relay.object_sent(&["live"], "video", sent(), None).expect("report");
    relay.close(Some(0)).expect("close");
    let stats = m.shutdown(Duration::from_secs(5)).await;
    assert_eq!(stats.bodies_queued, 0);

    let captured = mock.uploads();
    assert!(!captured.is_empty());
    assert!(!mock.clocks().is_empty(), "the clock probe goes through the tunnel too");
    for c in &captured {
        assert_eq!(c.header("authorization"), Some(format!("Bearer {KEY}").as_str()));
        assert!(c.uri.starts_with("/v1/source?i="), "{}", c.uri);
        read_body(&c.body, SOURCE);
    }
    let heads = proxy.heads();
    assert!(!heads.is_empty());
    let target = mock.addr.to_string();
    for head in &heads {
        assert!(head.starts_with(&format!("CONNECT {target} HTTP/1.1\r\n")), "{head}");
        // base64("alice:s:cret")
        assert!(head.contains("Proxy-Authorization: Basic YWxpY2U6czpjcmV0\r\n"), "{head}");
        assert!(!head.contains("mqt_sk_") && !head.contains("Bearer"), "{head}");
    }
}

#[tokio::test]
async fn a_refused_tunnel_keeps_the_body_queued() {
    let mock = Mock::start().await;
    let proxy = ConnectProxy::start("407 Proxy Authentication Required", "").await;
    let m = builder(&mock, Proxy::Url(proxy.url.clone())).start().expect("start");
    let relay = m.connection("https://relay.example.net/moq").expect("conn");
    relay.object_sent(&["live"], "video", sent(), None).expect("report");
    // A second CONNECT means the 407 came back as a retry.
    let end = tokio::time::Instant::now() + Duration::from_secs(5);
    while proxy.heads().len() < 2 && tokio::time::Instant::now() < end {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let stats = m.stats();
    assert!(proxy.heads().len() >= 2);
    assert_eq!(stats.bodies_sent, 0);
    assert_eq!(stats.bodies_lost, 0);
    assert!(stats.bodies_queued > 0);
    assert!(mock.captured().is_empty());
    m.shutdown(Duration::from_millis(200)).await;
}

#[tokio::test]
async fn direct_ignores_the_proxy_and_bad_proxies_are_refused_at_start() {
    let mock = Mock::start().await;
    let m = builder(&mock, Proxy::Direct).start().expect("start");
    let relay = m.connection("https://relay.example.net/moq").expect("conn");
    relay.object_sent(&["live"], "video", sent(), None).expect("report");
    m.shutdown(Duration::from_secs(5)).await;
    assert!(!mock.captured().is_empty());

    for bad in ["socks5://127.0.0.1:1080", "ftp://proxy", ""] {
        let e = builder(&mock, Proxy::Url(bad.into())).start();
        assert!(matches!(e, Err(Error::InvalidProxy)), "{bad}");
    }
}

/// Each request's path and body.
type Seen = Arc<Mutex<Vec<(String, Vec<u8>)>>>;

/// An https ingest with a self-signed certificate for 127.0.0.1: answers
/// every request, keeping each `(path, body)`.
struct TlsIngest {
    endpoint: String,
    cert: Vec<u8>,
    seen: Seen,
}

impl TlsIngest {
    async fn start() -> TlsIngest {
        let ck = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_string()]).unwrap();
        let cert = ck.cert.der().clone();
        let key = rustls::pki_types::PrivatePkcs8KeyDer::from(ck.signing_key.serialize_der());
        let server = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert.clone()], key.into())
        .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("https://{}", listener.local_addr().unwrap());
        let seen = Arc::new(Mutex::new(Vec::new()));
        let s = Arc::clone(&seen);
        tokio::spawn(async move {
            loop {
                let Ok((tcp, _)) = listener.accept().await else { return };
                let (acceptor, s) = (acceptor.clone(), Arc::clone(&s));
                tokio::spawn(async move {
                    let Ok(stream) = acceptor.accept(tcp).await else { return };
                    let svc = hyper::service::service_fn(move |req: Request<_>| {
                        let s = Arc::clone(&s);
                        async move {
                            let path = req.uri().to_string();
                            let body: hyper::body::Incoming = req.into_body();
                            let body = body.collect().await.map(|b| b.to_bytes().to_vec());
                            let status = if path == "/v1/clock" { 204 } else { 202 };
                            s.lock().unwrap().push((path, body.unwrap_or_default()));
                            Ok::<_, std::convert::Infallible>(
                                Response::builder()
                                    .status(status)
                                    .body(Full::new(Bytes::new()))
                                    .unwrap(),
                            )
                        }
                    });
                    let conn = hyper::server::conn::http1::Builder::new();
                    let _ = conn.serve_connection(TokioIo::new(stream), svc).await;
                });
            }
        });
        TlsIngest { endpoint, cert: cert.to_vec(), seen }
    }

    fn uploads(&self) -> Vec<Vec<u8>> {
        let seen = self.seen.lock().unwrap();
        seen.iter().filter(|(p, _)| p.starts_with("/v1/source")).map(|(_, b)| b.clone()).collect()
    }
}

#[tokio::test]
async fn test_roots_let_an_https_endpoint_be_reached_through_a_proxy() {
    let ingest = TlsIngest::start().await;
    let proxy = ConnectProxy::start("200 Connection established", "").await;
    let m = Monitor::builder(SOURCE, KEY)
        .endpoint(&ingest.endpoint)
        .proxy(Proxy::Url(proxy.url.clone()))
        .test_roots(vec![ingest.cert.clone()])
        .test_timing(Duration::from_millis(150), Duration::from_millis(20))
        .start()
        .expect("start");
    let relay = m.connection("https://relay.example.net/moq").expect("conn");
    relay.object_sent(&["live"], "video", sent(), None).expect("report");
    let stats = m.shutdown(Duration::from_secs(5)).await;
    assert!(stats.bodies_sent > 0);
    assert_eq!(stats.bodies_queued, 0);
    for body in ingest.uploads() {
        read_body(&body, SOURCE);
    }
    let target = ingest.endpoint.trim_start_matches("https://");
    let heads = proxy.heads();
    assert!(!heads.is_empty());
    assert!(heads.iter().all(|h| h.starts_with(&format!("CONNECT {target} HTTP/1.1\r\n"))));
}

#[tokio::test]
async fn without_test_roots_the_self_signed_endpoint_is_not_trusted() {
    let ingest = TlsIngest::start().await;
    let m = Monitor::builder(SOURCE, KEY)
        .endpoint(&ingest.endpoint)
        .proxy(Proxy::Direct)
        .test_timing(Duration::from_millis(150), Duration::from_millis(20))
        .start()
        .expect("start");
    let relay = m.connection("https://relay.example.net/moq").expect("conn");
    relay.object_sent(&["live"], "video", sent(), None).expect("report");
    let stats = m.shutdown(Duration::from_millis(500)).await;
    assert_eq!(stats.bodies_sent, 0);
    assert!(ingest.uploads().is_empty());
}
