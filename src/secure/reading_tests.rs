//! What the proxy reads from a source, encrypted with a network key: a file, an answer over HTTP,
//! the answer of a url of `real_time_configurations` - docs/encrypted-service-data.md.
//!
//! The network keys of the proxy are shared by the tests which run at the same time, so every
//! test here sets the same one key: a source encrypted with any other key is one the proxy can
//! not open.

use std::{sync::Arc, time::Duration};

use my_ssh::ssh_settings::OverSshConnectionSettings;
use parking_lot::Mutex;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};
use zeroize::Zeroizing;

use super::aes128gcm;
use crate::app::APP_CTX;

const NETWORK_KEY: [u8; 32] = [0x5a; 32];
const ANOTHER_KEY: [u8; 32] = [0xa5; 32];

const PEM: &[u8] = b"-----BEGIN CERTIFICATE-----\nMIIBfake\n-----END CERTIFICATE-----\n";

fn use_the_network_key() {
    APP_CTX
        .secure
        .network_keys
        .set(vec![Zeroizing::new(NETWORK_KEY)]);
}

fn temporary_file(name: &str, content: &[u8]) -> String {
    let path = std::env::temp_dir().join(format!(
        "my-reverse-proxy-reading-{name}-{}",
        std::process::id()
    ));
    std::fs::write(&path, content).unwrap();
    path.to_str().unwrap().to_string()
}

async fn load(source: &str) -> Result<Vec<u8>, String> {
    let source = OverSshConnectionSettings::try_parse(source).unwrap();
    crate::scripts::load_file(&source, Duration::from_secs(2)).await
}

/// A server which answers every request with `body` - with `Content-Encoding` when it is given -
/// and keeps the head of the last request it was sent.
async fn serve(content_encoding: Option<&str>, body: Vec<u8>) -> (u16, Arc<Mutex<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let mut response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/yaml\r\nContent-Length: {}\r\nConnection: close\r\n",
        body.len()
    );
    if let Some(content_encoding) = content_encoding {
        response.push_str(&format!("Content-Encoding: {content_encoding}\r\n"));
    }
    response.push_str("\r\n");

    let mut response = response.into_bytes();
    response.extend_from_slice(&body);

    let last_head = Arc::new(Mutex::new(String::new()));
    let kept = last_head.clone();

    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };

            let response = response.clone();
            let kept = kept.clone();

            tokio::spawn(async move {
                let mut head = Vec::new();
                let mut buffer = [0u8; 4096];

                while !head.windows(4).any(|window| window == b"\r\n\r\n") {
                    match stream.read(&mut buffer).await {
                        Ok(0) | Err(_) => return,
                        Ok(read) => head.extend_from_slice(&buffer[..read]),
                    }
                }

                *kept.lock() = String::from_utf8_lossy(&head).to_ascii_lowercase();

                let _ = stream.write_all(&response).await;
                let _ = stream.shutdown().await;
            });
        }
    });

    (port, last_head)
}

#[tokio::test]
async fn an_encrypted_file_is_decrypted_and_a_plain_one_is_read_as_it_is() {
    use_the_network_key();

    let encrypted = temporary_file("encrypted", &aes128gcm::encrypt(&NETWORK_KEY, PEM));
    let plain = temporary_file("plain", PEM);
    let foreign = temporary_file("foreign", &aes128gcm::encrypt(&ANOTHER_KEY, PEM));

    let from_encrypted = load(&encrypted).await;
    let from_plain = load(&plain).await;
    let from_foreign = load(&foreign).await;

    for path in [&encrypted, &plain, &foreign] {
        std::fs::remove_file(path).unwrap();
    }

    assert_eq!(from_encrypted.unwrap(), PEM);
    assert_eq!(from_plain.unwrap(), PEM);

    // Encrypted with a key the proxy does not have: it is not opened, and is read as it is - the
    // parser of the certificate refuses it then.
    assert_ne!(from_foreign.unwrap(), PEM);
}

#[tokio::test]
async fn an_encrypted_answer_over_http_is_decrypted() {
    use_the_network_key();

    let (marked, marked_head) =
        serve(Some("aes128gcm"), aes128gcm::encrypt(&NETWORK_KEY, PEM)).await;
    let (unmarked, _) = serve(None, aes128gcm::encrypt(&NETWORK_KEY, PEM)).await;
    let (plain, _) = serve(None, PEM.to_vec()).await;

    assert_eq!(
        load(&format!("http://127.0.0.1:{marked}/cert.pem"))
            .await
            .unwrap(),
        PEM
    );
    assert!(
        marked_head.lock().contains("accept-encoding: aes128gcm"),
        "{}",
        marked_head.lock()
    );

    assert_eq!(
        load(&format!("http://127.0.0.1:{unmarked}/cert.pem"))
            .await
            .unwrap(),
        PEM
    );
    assert_eq!(
        load(&format!("http://127.0.0.1:{plain}/cert.pem"))
            .await
            .unwrap(),
        PEM
    );
}

/// An answer which says it is encrypted is never taken as it is.
#[tokio::test]
async fn a_marked_answer_none_of_the_keys_opens_is_an_error() {
    use_the_network_key();

    let (port, _) = serve(Some("aes128gcm"), aes128gcm::encrypt(&ANOTHER_KEY, PEM)).await;

    let err = load(&format!("http://127.0.0.1:{port}/cert.pem"))
        .await
        .unwrap_err();

    assert!(err.contains("none of the 1 network keys"), "{err}");
    assert!(err.contains(&format!("127.0.0.1:{port}")), "{err}");
}

#[tokio::test]
async fn a_real_time_answer_is_decrypted_before_it_is_parsed() {
    use_the_network_key();

    let yaml = b"ip_white_lists:\n  office:\n  - 10.0.0.1\n";

    for content_encoding in [Some("aes128gcm"), None] {
        let (port, head) = serve(content_encoding, aes128gcm::encrypt(&NETWORK_KEY, yaml)).await;

        let model = crate::flows::read_real_time_configuration(
            &format!("http://127.0.0.1:{port}/hosts"),
            Duration::from_secs(2),
        )
        .await
        .unwrap_or_else(|err| panic!("{content_encoding:?}: {err}"))
        .unwrap();

        assert_eq!(model.ip_white_lists["office"], ["10.0.0.1"]);
        assert!(head.lock().contains("accept-encoding: aes128gcm"));
    }

    let (port, _) = serve(Some("aes128gcm"), aes128gcm::encrypt(&ANOTHER_KEY, yaml)).await;

    let err = crate::flows::read_real_time_configuration(
        &format!("http://127.0.0.1:{port}/hosts"),
        Duration::from_secs(2),
    )
    .await
    .unwrap_err();

    assert!(err.contains("none of the 1 network keys"), "{err}");
}
