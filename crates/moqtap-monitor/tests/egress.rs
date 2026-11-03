//! Uploads through a local HTTP `CONNECT` proxy.

mod common;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::{read_body, Mock};
use moqtap_monitor::{Error, Monitor, Proxy};
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
        .seal_interval(Duration::from_millis(150))
}

#[tokio::test]
async fn uploads_go_through_the_tunnel_and_the_key_stays_inside_it() {
    let mock = Mock::start().await;
    let proxy = ConnectProxy::start("200 Connection established", "alice:s%3Acret@").await;
    let m = builder(&mock, Proxy::Url(proxy.url.clone())).start().expect("start");
    let relay = m.connection("https://relay.example.net/moq").expect("conn");
    relay.object_sent(&["live"], "video", 0, 0, 100, None).expect("report");
    relay.close(Some(0)).expect("close");
    let stats = m.shutdown(Duration::from_secs(5)).await;
    assert_eq!(stats.bodies_queued, 0);

    let captured = mock.captured();
    assert!(!captured.is_empty());
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
    relay.object_sent(&["live"], "video", 0, 0, 100, None).expect("report");
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
    relay.object_sent(&["live"], "video", 0, 0, 100, None).expect("report");
    m.shutdown(Duration::from_secs(5)).await;
    assert!(!mock.captured().is_empty());

    for bad in ["socks5://127.0.0.1:1080", "ftp://proxy", ""] {
        let e = builder(&mock, Proxy::Url(bad.into())).start();
        assert!(matches!(e, Err(Error::InvalidProxy)), "{bad}");
    }
}
