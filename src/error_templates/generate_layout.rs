use std::sync::LazyLock;

use rust_extensions::StrOrString;
use x509_parser::nom::AsBytes;

pub static NOT_FOUND: LazyLock<Vec<u8>> =
    LazyLock::new(|| generate_layout(404, "Resource not found", None));

pub static BAD_REQUEST: LazyLock<Vec<u8>> =
    LazyLock::new(|| generate_layout(400, "Bad Request", None));

pub static REMOTE_RESOURCE_IS_NOT_AVAILABLE: LazyLock<Vec<u8>> = LazyLock::new(|| {
    generate_layout(
        503,
        "Server Error",
        Some("Remote resource is not available".into()),
    )
});

pub static LOCATION_IS_NOT_FOUND: LazyLock<Vec<u8>> = LazyLock::new(|| {
    generate_layout_with_close(
        503,
        "Server Error",
        Some("Remote location configuration is missing".into()),
    )
});

pub static ERROR_TIMEOUT: LazyLock<Vec<u8>> =
    LazyLock::new(|| generate_layout(503, "Server Error", Some("Timeout".into())));

pub static ERROR_GETTING_CONTENT_FROM_REMOTE_RESOURCE: LazyLock<Vec<u8>> =
    LazyLock::new(|| generate_layout(502, "Server Error", Some("Bad gateway".into())));

pub static UPSTREAM_IS_NOT_HTTP: LazyLock<Vec<u8>> = LazyLock::new(|| {
    generate_layout(
        502,
        "Server Error",
        Some("Upstream is not a valid HTTP server".into()),
    )
});

pub static NOT_AUTHORIZED_PAGE: LazyLock<Vec<u8>> =
    LazyLock::new(|| generate_layout(401, "Not authorized request", None));

pub static PROXY_TO_HEADER_MISSING: LazyLock<Vec<u8>> = LazyLock::new(|| {
    build_layout_with_explicit_status(
        421,
        "Misdirected Request",
        Some("Missing or invalid proxy-to header".into()),
    )
});

pub static PROXY_TO_HOST_NOT_ALLOWED: LazyLock<Vec<u8>> = LazyLock::new(|| {
    build_layout_with_explicit_status(403, "Forbidden", Some("Upstream host not allowed".into()))
});

pub static MTLS_REQUIRED_MISDIRECTED: LazyLock<Vec<u8>> = LazyLock::new(|| {
    build_layout_with_explicit_status(
        421,
        "Misdirected Request",
        Some("A client certificate is required for this host".into()),
    )
});

pub fn generate_layout(status_code: u16, text: &str, second_line: Option<StrOrString>) -> Vec<u8> {
    build_layout(status_code, text, second_line, false)
}

/// The page of [`generate_layout`] alone - the html, with no status line and no headers.
///
/// `generate_layout` gives a whole HTTP/1.1 response, for the h1 server to write to the socket
/// as it is. The hyper path makes its own head: given the whole response for a body, it would
/// send `HTTP/1.1 404 ...` and the headers as the first lines of the page.
pub fn generate_layout_body(
    status_code: u16,
    text: &str,
    second_line: Option<StrOrString>,
) -> Vec<u8> {
    layout_body(status_code, text, second_line)
}

pub fn generate_layout_with_close(
    status_code: u16,
    text: &str,
    second_line: Option<StrOrString>,
) -> Vec<u8> {
    build_layout(status_code, text, second_line, true)
}

/// Like `build_layout` but writes the actual status code on the response line
/// instead of hardcoding `200 OK`. Used by templates that need to drive client
/// behavior via HTTP status (e.g. 421 Misdirected Request, 403 Forbidden).
fn build_layout_with_explicit_status(
    status_code: u16,
    text: &str,
    second_line: Option<StrOrString>,
) -> Vec<u8> {
    use crate::app::APP_VERSION;

    let second_line = if let Some(second_line) = second_line {
        format!("<h4>{}</h4>", second_line.as_str())
    } else {
        "".to_string()
    };

    let body = format!(
        r#"
        <div style="text-align: center;">
        <h2>{text}</h2>
      {second_line}
        <p>{status_code}</p>
        <hr/>
        <div>MyReverseProxy {APP_VERSION}</div>
        </div>
        "#
    )
    .into_bytes();

    let mut headers = crate::h1_utils::Http1HeadersBuilder::new();
    headers.push_response_first_line(status_code);
    headers.push_content_length(body.len());
    headers.push_cl_cr();

    let mut result = headers.into_bytes();
    result.extend_from_slice(body.as_bytes());
    result
}

fn layout_body(status_code: u16, text: &str, second_line: Option<StrOrString>) -> Vec<u8> {
    use crate::app::APP_VERSION;

    let second_line = if let Some(second_line) = second_line {
        format!("<h4>{}</h4>", second_line.as_str())
    } else {
        "".to_string()
    };

    format!(
        r#"
        <div style="text-align: center;">
        <h2>{text}</h2>
      {second_line}
        <p>{status_code}</p>
        <hr/>
        <div>MyReverseProxy {APP_VERSION}</div>
        </div>
        "#
    )
    .into_bytes()
}

fn build_layout(
    status_code: u16,
    text: &str,
    second_line: Option<StrOrString>,
    connection_close: bool,
) -> Vec<u8> {
    let body = layout_body(status_code, text, second_line);

    let mut headers = crate::h1_utils::Http1HeadersBuilder::new();
    headers.push_response_first_line(status_code);

    headers.push_content_length(body.len());
    if connection_close {
        headers.push_header("Connection", "close");
    }
    headers.push_cl_cr();

    let mut result = headers.into_bytes();
    result.extend_from_slice(body.as_bytes());
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The h1 server writes the whole response; the hyper path takes the page alone.
    #[test]
    fn the_page_alone_has_no_head() {
        let response = String::from_utf8(generate_layout(404, "Not found", None)).unwrap();
        let page = String::from_utf8(generate_layout_body(404, "Not found", None)).unwrap();

        assert!(response.starts_with("HTTP/1.1 404 "), "{response}");
        assert!(response.ends_with(&page));

        assert!(!page.contains("HTTP/1.1"), "{page}");
        assert!(!page.contains("content-length"), "{page}");
        assert!(page.contains("<h2>Not found</h2>"), "{page}");
    }
}
