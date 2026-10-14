use bytes::Bytes;
use http_body_util::{combinators::BoxBody, BodyExt, Full};

use crate::configurations::NotServedReason;

/// What an endpoint which serves nobody answers on the h1 path, and what a `type: mcp`
/// endpoint writes to a debug ip before it closes: a whole HTTP/1.1 response.
///
/// Everybody gets a bare `403 Forbidden`: it says nothing about the proxy or how it is set
/// up. A source listed in `global_settings.debug_ip` gets the reason on the page.
pub fn not_served_h1_response(reason: &NotServedReason, is_debug_ip: bool) -> Vec<u8> {
    let second_line = is_debug_ip.then(|| super::html_escape(reason.as_str()).into());

    super::generate_layout_with_close(403, "Forbidden", second_line)
}

/// The same answer on the hyper path.
pub fn not_served_hyper_response(
    reason: &NotServedReason,
    is_debug_ip: bool,
) -> hyper::Response<BoxBody<Bytes, String>> {
    let body = if is_debug_ip {
        format!("Forbidden\n\n{}\n", reason.as_str())
    } else {
        "Forbidden".to_string()
    };

    hyper::Response::builder()
        .status(hyper::StatusCode::FORBIDDEN)
        .header(hyper::header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(
            Full::new(Bytes::from(body))
                .map_err(crate::to_hyper_error)
                .boxed(),
        )
        .unwrap()
}

/// What a `type: tcp` endpoint which serves nobody writes to a debug ip before it closes the
/// connection. There is no protocol to answer in, so it is a line of text. Everybody else gets
/// the close alone.
pub fn not_served_text(reason: &NotServedReason) -> String {
    format!("{}\n", reason.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reason() -> NotServedReason {
        NotServedReason::new(
            "localhost:443",
            "mcp",
            &["auth_header"],
            "a raw bridge with no HTTP layer",
            "remove <the setting>",
        )
        .unwrap()
    }

    #[test]
    fn everybody_gets_a_bare_403_on_the_h1_path() {
        let response = String::from_utf8(not_served_h1_response(&reason(), false)).unwrap();

        assert!(response.starts_with("HTTP/1.1 403 "), "{response}");
        assert!(response.contains("Forbidden"));
        assert!(!response.contains("auth_header"), "{response}");
        assert!(!response.contains("localhost:443"), "{response}");
        assert!(!response.contains("mcp"), "{response}");
    }

    #[test]
    fn a_debug_ip_gets_the_reason_on_the_h1_path() {
        let response = String::from_utf8(not_served_h1_response(&reason(), true)).unwrap();

        assert!(response.starts_with("HTTP/1.1 403 "), "{response}");
        assert!(response.contains("&#39;auth_header&#39;") || response.contains("'auth_header'"));
        assert!(response.contains("localhost:443"));
        // The reason goes into a page: what is in it is escaped.
        assert!(
            response.contains("remove &lt;the setting&gt;"),
            "{response}"
        );
    }

    #[tokio::test]
    async fn the_hyper_path_answers_the_same_way() {
        let response = not_served_hyper_response(&reason(), false);
        assert_eq!(response.status(), 403);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body, "Forbidden");

        let response = not_served_hyper_response(&reason(), true);
        assert_eq!(response.status(), 403);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let body = String::from_utf8(body.to_vec()).unwrap();
        assert!(body.starts_with("Forbidden\n\n"), "{body}");
        assert!(body.contains("'auth_header'"), "{body}");
        assert!(body.contains("localhost:443"), "{body}");
    }

    #[test]
    fn a_tcp_endpoint_writes_the_reason_as_a_line() {
        let text = not_served_text(&reason());
        assert!(text.starts_with("Endpoint 'localhost:443' is 'type: mcp'"));
        assert!(text.ends_with('\n'));
    }
}
