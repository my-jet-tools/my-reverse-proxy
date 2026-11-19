//! Sends one call of the encrypted API of the control port, and prints the answer, decrypted.
//!
//! Usage:
//!     encrypted_call <control port> <route> <key file> [<body file>]
//!
//! <control port>  where the control port is: `http://127.0.0.1:8000`, or its unix socket,
//!                 `http+unix:///var/run/my-reverse-proxy/control.sock`.
//! <route>         `/api/private-keys/v1/set`, `/api/private-keys/v1/generate`,
//!                 `/api/gateway-connections/v1/set`, `/api/mcp/v1/admin-mode`, ...
//! <key file>      a file with a network key: base64 of 32 bytes. The key is read from a file,
//!                 never from the command line, so it is left neither in the history of the shell
//!                 nor in a chat.
//! <body file>     the JSON of the call; `-` or nothing: the standard input. The list takes `{}`.
//!
//! Example - a private key for the gateway client with `private_key: london`:
//!     jq -n --rawfile key london.key '{id: "london", private_key: $key}' \
//!       | encrypted_call http://127.0.0.1:8000 /api/private-keys/v1/set ~/.network-key
//!
//! The body goes encrypted with the key (my-http-utils' EncryptedBody: the sender's clock, then
//! the JSON - fl-url's `encrypted`). An encrypted answer is opened with the same key. Exits with 0
//! on a 2xx answer, 1 on any other or on a failure, and 2 on a wrong command line.

use std::io::Read;

use my_http_server::{HttpBodyEncryptionKey, AES128GCM_CONTENT_ENCODING};
use my_http_utils::body::HttpRequestBody;

const USAGE: &str = "Usage: encrypted_call <control port> <route> <key file> [<body file>]";

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();

    if args.len() < 3 || args.len() > 4 {
        eprintln!("{USAGE}");
        std::process::exit(2);
    }

    match call(
        &args[0],
        &args[1],
        &args[2],
        args.get(3).map(String::as_str),
    )
    .await
    {
        Ok((status, answer)) => {
            println!("{answer}");

            if !(200..300).contains(&status) {
                eprintln!("The control port answered {status}");
                std::process::exit(1);
            }
        }
        Err(err) => {
            eprintln!("{err}");
            std::process::exit(1);
        }
    }
}

/// The status of the answer, and the answer as text - decrypted if it came encrypted.
async fn call(
    control_port: &str,
    route: &str,
    key_file: &str,
    body_file: Option<&str>,
) -> Result<(u16, String), String> {
    let key_text = std::fs::read_to_string(key_file)
        .map_err(|err| format!("The key file {key_file} can not be read: {err}"))?;

    let key = HttpBodyEncryptionKey::from_base64(key_text.trim())
        .map_err(|err| format!("The key file {key_file} holds no network key: {err}"))?;

    let body = match body_file {
        None | Some("-") => {
            let mut body = Vec::new();
            std::io::stdin()
                .read_to_end(&mut body)
                .map_err(|err| format!("The standard input can not be read: {err}"))?;
            body
        }
        Some(path) => std::fs::read(path)
            .map_err(|err| format!("The body file {path} can not be read: {err}"))?,
    };

    let mut url = flurl::FlUrl::new(control_port.trim_end_matches('/'));

    for segment in route.split('/').filter(|segment| !segment.is_empty()) {
        url = url.append_path_segment(segment);
    }

    let mut response = url
        .encrypted(&key)
        .post(HttpRequestBody::from_raw_data(
            body,
            Some("application/json"),
        ))
        .await
        .map_err(|err| format!("The call failed: {err:?}"))?;

    let status = response.get_status_code();

    let is_encrypted = response
        .get_header("content-encoding")
        .ok()
        .flatten()
        .is_some_and(|value| {
            value
                .trim()
                .eq_ignore_ascii_case(AES128GCM_CONTENT_ENCODING)
        });

    let answer = response
        .get_body()
        .map_err(|err| format!("The answer can not be read: {err:?}"))?
        .into_vec(usize::MAX)
        .await
        .map_err(|err| format!("The answer can not be read: {err:?}"))?;

    let answer = if is_encrypted {
        key.decrypt(&answer)
            .map_err(|err| format!("The answer does not open with the key: {err}"))?
    } else {
        answer
    };

    Ok((status, String::from_utf8_lossy(&answer).into_owned()))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use my_http_server::EncryptedBody;
    use parking_lot::Mutex;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    /// A server which takes one call, keeps its head and body, and answers `answer` encrypted with
    /// `key`.
    async fn serve_once(
        key: HttpBodyEncryptionKey,
        answer: &'static [u8],
    ) -> (u16, Arc<Mutex<(String, Vec<u8>)>>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let kept = Arc::new(Mutex::new((String::new(), Vec::new())));
        let kept_by_server = kept.clone();

        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();

            let mut received = Vec::new();
            let mut buffer = [0u8; 4096];

            let head_end = loop {
                let read = stream.read(&mut buffer).await.unwrap();
                received.extend_from_slice(&buffer[..read]);
                if let Some(at) = received.windows(4).position(|w| w == b"\r\n\r\n") {
                    break at + 4;
                }
            };

            let head = String::from_utf8_lossy(&received[..head_end]).to_ascii_lowercase();
            let length: usize = head
                .lines()
                .find_map(|line| line.strip_prefix("content-length:"))
                .map(|value| value.trim().parse().unwrap())
                .unwrap_or(0);

            while received.len() < head_end + length {
                let read = stream.read(&mut buffer).await.unwrap();
                received.extend_from_slice(&buffer[..read]);
            }

            *kept_by_server.lock() = (head, received[head_end..head_end + length].to_vec());

            let body = key.encrypt(answer);
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Encoding: aes128gcm\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            stream.write_all(response.as_bytes()).await.unwrap();
            stream.write_all(&body).await.unwrap();
            let _ = stream.shutdown().await;
        });

        (port, kept)
    }

    /// The call goes encrypted - the clock of the sender, then the JSON - and the answer is opened
    /// with the same key.
    #[tokio::test]
    async fn a_call_goes_encrypted_and_its_answer_is_opened() {
        let key_bytes = [0x5au8; 32];
        let key = HttpBodyEncryptionKey::from_bytes(&key_bytes).unwrap();

        let key_file =
            std::env::temp_dir().join(format!("encrypted-call-key-{}", std::process::id()));
        let body_file =
            std::env::temp_dir().join(format!("encrypted-call-body-{}", std::process::id()));
        std::fs::write(
            &key_file,
            format!(
                "{}\n",
                base64::Engine::encode(&base64::engine::general_purpose::STANDARD, key_bytes)
            ),
        )
        .unwrap();
        std::fs::write(&body_file, br#"{"id": "london"}"#).unwrap();

        let (port, kept) = serve_once(key.clone(), br#"{"id":"london","deleted":true}"#).await;

        let result = call(
            &format!("http://127.0.0.1:{port}"),
            "/api/private-keys/v1/delete",
            key_file.to_str().unwrap(),
            Some(body_file.to_str().unwrap()),
        )
        .await;

        std::fs::remove_file(&key_file).unwrap();
        std::fs::remove_file(&body_file).unwrap();

        let (status, answer) = result.unwrap();
        assert_eq!(status, 200);
        assert_eq!(answer, r#"{"id":"london","deleted":true}"#);

        let (head, body) = kept.lock().clone();
        assert!(
            head.starts_with("post /api/private-keys/v1/delete "),
            "{head}"
        );
        assert!(head.contains("content-encoding: aes128gcm"), "{head}");

        let opened = EncryptedBody::decrypt(&body, &key).unwrap();
        assert_eq!(opened.body, br#"{"id": "london"}"#);
    }
}
