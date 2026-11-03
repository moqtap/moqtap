//! A Linux host without a CA store, such as a slim or distroless image. The
//! only test in this binary, since it sets the process environment.

#![cfg(all(unix, not(target_os = "android"), not(target_vendor = "apple")))]

use std::sync::Arc;
use std::time::Duration;

use moqtap_monitor::{Monitor, Proxy};

#[tokio::test]
async fn start_falls_back_to_mozillas_roots() {
    let dir = std::env::temp_dir().join(format!("moqtap-monitor-no-ca-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("dir");
    let file = dir.join("empty.pem");
    std::fs::write(&file, b"").expect("file");
    std::env::set_var("SSL_CERT_FILE", &file);
    std::env::set_var("SSL_CERT_DIR", &dir);

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    assert!(rustls_platform_verifier::Verifier::new(provider).is_err());
    let m = Monitor::builder("enc-test-1", "mqt_sk_AAAAtestkeybody_testmac")
        .endpoint("https://127.0.0.1:9")
        .proxy(Proxy::Direct)
        .start();
    let _ = std::fs::remove_dir_all(&dir);
    m.expect("start").shutdown(Duration::from_millis(100)).await;
}
