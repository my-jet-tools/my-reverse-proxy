use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};

use crate::configurations::HttpListenPortConfiguration;
use crate::error_templates::DebugPageSection;
use crate::http_proxy_pass::ProxyPassError;
use crate::types::ConnectionIp;

/// A request refused before it reached a location: the response to answer with.
/// Boxed, because the lookup it comes from runs for every request and its `Ok`
/// is a single `Arc`.
pub type RejectedRequest = Box<hyper::Response<BoxBody<Bytes, String>>>;

pub fn create_err_response(
    status_code: hyper::StatusCode,
    content: impl Into<Bytes>,
) -> RejectedRequest {
    let result = hyper::Response::builder()
        .status(status_code)
        .body(
            Full::new(content.into())
                .map_err(crate::to_hyper_error)
                .boxed(),
        )
        .unwrap();

    Box::new(result)
}

fn create_err_response_with_content_type(
    status_code: hyper::StatusCode,
    content_type: &'static str,
    content: impl Into<Bytes>,
) -> RejectedRequest {
    let result = hyper::Response::builder()
        .status(status_code)
        .header(hyper::header::CONTENT_TYPE, content_type)
        .body(
            Full::new(content.into())
                .map_err(crate::to_hyper_error)
                .boxed(),
        )
        .unwrap();

    Box::new(result)
}

/// Why a request was refused before an endpoint was resolved for it.
pub enum BadRequestReason<'s> {
    /// Neither the request uri nor the `Host` header names a host.
    HostNotDetected,
    /// No endpoint of this listener is configured for the request's host.
    NoConfigurationForHost(&'s str),
}

/// The answer to a request refused before an endpoint was resolved for it.
///
/// A source listed in `global_settings.debug_ip` gets an HTML page saying what
/// the proxy saw and what it tried to match it against. Everybody else gets a
/// bare `400 Bad Request`, which tells nothing about the proxy or what it
/// serves.
pub fn create_bad_request_response<B>(
    connection_ip: &ConnectionIp,
    req: &hyper::Request<B>,
    listen_port_config: &HttpListenPortConfiguration,
    reason: BadRequestReason,
) -> RejectedRequest {
    let is_debug_ip = crate::app::APP_CTX.debug_ip.is_debug_ip(connection_ip);

    bad_request_response(is_debug_ip, connection_ip, req, listen_port_config, reason)
}

fn bad_request_response<B>(
    is_debug_ip: bool,
    connection_ip: &ConnectionIp,
    req: &hyper::Request<B>,
    listen_port_config: &HttpListenPortConfiguration,
    reason: BadRequestReason,
) -> RejectedRequest {
    if !is_debug_ip {
        return create_err_response_with_content_type(
            hyper::StatusCode::BAD_REQUEST,
            "text/plain",
            "Bad Request",
        );
    }

    let (text, description) = match reason {
        BadRequestReason::HostNotDetected => (
            "Can not detect host",
            "Neither the request uri nor the Host header names a host".to_string(),
        ),
        BadRequestReason::NoConfigurationForHost(host) => (
            "No configuration found",
            format!("No endpoint of this listener is configured for host '{host}'"),
        ),
    };

    let none = || "(none)".to_string();

    let client_ip = match connection_ip.get_ip_log() {
        Some(ip) => format!("{ip} (listed in global_settings.debug_ip)"),
        None => "unix socket".to_string(),
    };

    let request = DebugPageSection {
        title: "Request",
        rows: vec![
            ("Client ip".to_string(), client_ip),
            ("Method".to_string(), req.method().to_string()),
            ("Uri".to_string(), req.uri().to_string()),
            ("Version".to_string(), format!("{:?}", req.version())),
            (
                "Host in uri".to_string(),
                req.uri().host().map(str::to_string).unwrap_or_else(none),
            ),
            (
                "Host header".to_string(),
                req.headers()
                    .get(hyper::header::HOST)
                    .map(header_value_to_string)
                    .unwrap_or_else(none),
            ),
        ],
    };

    let listener = DebugPageSection {
        title: "Listener",
        rows: vec![
            (
                "Listening on".to_string(),
                listen_port_config.listen_host.to_string(),
            ),
            (
                "Type".to_string(),
                format!("{:?}", listen_port_config.listen_endpoint_type),
            ),
        ],
    };

    let configured_hosts = DebugPageSection {
        title: "Hosts configured on this listener",
        rows: listen_port_config
            .endpoints
            .iter()
            .map(|endpoint| {
                (
                    endpoint.host_endpoint.as_str().to_string(),
                    format!("{:?}", endpoint.listen_endpoint_type),
                )
            })
            .collect(),
    };

    let headers = DebugPageSection {
        title: "Request headers",
        rows: req
            .headers()
            .iter()
            .map(|(name, value)| (name.as_str().to_string(), header_value_to_string(value)))
            .collect(),
    };

    let page = crate::error_templates::generate_debug_page(
        400,
        text,
        description.as_str(),
        &[request, listener, configured_hosts, headers],
    );

    create_err_response_with_content_type(
        hyper::StatusCode::BAD_REQUEST,
        "text/html; charset=utf-8",
        page,
    )
}

fn header_value_to_string(value: &hyper::header::HeaderValue) -> String {
    String::from_utf8_lossy(value.as_bytes()).to_string()
}

pub fn generate_tech_page(
    err: ProxyPassError,
    show_error_description: bool,
) -> hyper::Response<BoxBody<Bytes, String>> {
    let second_line_error = if show_error_description {
        Some(format!("{err:?}").into())
    } else {
        None
    };

    match err {
        ProxyPassError::Timeout => {
            let body: Bytes =
                crate::error_templates::generate_layout(504, "Timeout", second_line_error).into();
            let body = Full::new(body).map_err(crate::to_hyper_error).boxed();
            hyper::Response::builder()
                .status(hyper::StatusCode::GATEWAY_TIMEOUT)
                .body(body)
                .unwrap()
        }
        ProxyPassError::NoLocationFound => {
            let body: Bytes =
                crate::error_templates::generate_layout(404, "Not found", second_line_error).into();

            hyper::Response::builder()
                .status(hyper::StatusCode::NOT_FOUND)
                .body(Full::from(body).map_err(crate::to_hyper_error).boxed())
                .unwrap()
        }

        ProxyPassError::Unauthorized => hyper::Response::builder()
            .status(hyper::StatusCode::UNAUTHORIZED)
            .body(
                Full::from(crate::error_templates::generate_layout(
                    401,
                    "Unauthorized request",
                    second_line_error,
                ))
                .map_err(crate::to_hyper_error)
                .boxed(),
            )
            .unwrap(),

        ProxyPassError::UserIsForbidden => hyper::Response::builder()
            .status(hyper::StatusCode::FORBIDDEN)
            .body(
                Full::from(crate::error_templates::generate_layout(
                    403,
                    "Access is forbidden",
                    second_line_error,
                ))
                .map_err(crate::to_hyper_error)
                .boxed(),
            )
            .unwrap(),

        ProxyPassError::IpRestricted(ip) => hyper::Response::builder()
            .status(hyper::StatusCode::UNAUTHORIZED)
            .body(
                Full::from(crate::error_templates::generate_layout(
                    401,
                    "Restricted by IP",
                    Some(ip.as_str().into()),
                ))
                .map_err(crate::to_hyper_error)
                .boxed(),
            )
            .unwrap(),
        ProxyPassError::UpstreamUnavailable => hyper::Response::builder()
            .status(hyper::StatusCode::SERVICE_UNAVAILABLE)
            .body(
                Full::from(crate::error_templates::generate_layout(
                    503,
                    "Upstream unavailable",
                    second_line_error,
                ))
                .map_err(crate::to_hyper_error)
                .boxed(),
            )
            .unwrap(),
        ProxyPassError::ProxyToHeaderMissing | ProxyPassError::ProxyToHeaderInvalid => {
            hyper::Response::builder()
                .status(hyper::StatusCode::MISDIRECTED_REQUEST)
                .body(
                    Full::from(crate::error_templates::generate_layout(
                        421,
                        "Missing or invalid proxy-to header",
                        second_line_error,
                    ))
                    .map_err(crate::to_hyper_error)
                    .boxed(),
                )
                .unwrap()
        }
        ProxyPassError::ProxyToHostNotAllowed => hyper::Response::builder()
            .status(hyper::StatusCode::FORBIDDEN)
            .body(
                Full::from(crate::error_templates::generate_layout(
                    403,
                    "Upstream host not allowed",
                    second_line_error,
                ))
                .map_err(crate::to_hyper_error)
                .boxed(),
            )
            .unwrap(),
        // Upstream transport-level failures: the proxy itself is healthy, the
        // upstream misbehaved — surface them as gateway errors, not 500.
        ProxyPassError::MyHttpClientError(err) => {
            let (status, code, title) =
                if matches!(err, my_http_client::MyHttpClientError::RequestTimeout(_)) {
                    (hyper::StatusCode::GATEWAY_TIMEOUT, 504, "Upstream timeout")
                } else {
                    (hyper::StatusCode::BAD_GATEWAY, 502, "Bad gateway")
                };
            hyper::Response::builder()
                .status(status)
                .body(
                    Full::from(crate::error_templates::generate_layout(
                        code,
                        title,
                        second_line_error,
                    ))
                    .map_err(crate::to_hyper_error)
                    .boxed(),
                )
                .unwrap()
        }
        _ => hyper::Response::builder()
            .status(hyper::StatusCode::INTERNAL_SERVER_ERROR)
            .body(
                Full::from(crate::error_templates::generate_layout(
                    500,
                    "Internal Server Error",
                    second_line_error,
                ))
                .map_err(crate::to_hyper_error)
                .boxed(),
            )
            .unwrap(),
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use crate::configurations::ListenHttpEndpointType;

    use super::*;

    fn listen_port_config() -> HttpListenPortConfiguration {
        HttpListenPortConfiguration {
            endpoints: vec![],
            listen_endpoint_type: ListenHttpEndpointType::Https2,
            listen_host: "0.0.0.0:443".parse::<SocketAddr>().unwrap().into(),
        }
    }

    fn request() -> hyper::Request<()> {
        hyper::Request::builder()
            .method("GET")
            .uri("/some/path?a=1")
            .header("host", "unknown.example.com")
            .header("x-probe", "<script>alert(1)</script>")
            .body(())
            .unwrap()
    }

    async fn read(response: RejectedRequest) -> (hyper::StatusCode, String, String) {
        let status = response.status();
        let content_type = response
            .headers()
            .get(hyper::header::CONTENT_TYPE)
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        let body = response.into_body().collect().await.unwrap().to_bytes();

        (
            status,
            content_type,
            String::from_utf8(body.to_vec()).unwrap(),
        )
    }

    #[tokio::test]
    async fn everybody_else_gets_a_bare_bad_request() {
        let connection_ip = ConnectionIp::Tcp("10.0.0.5:5000".parse().unwrap());

        let response = bad_request_response(
            false,
            &connection_ip,
            &request(),
            &listen_port_config(),
            BadRequestReason::NoConfigurationForHost("unknown.example.com"),
        );

        let (status, content_type, body) = read(response).await;

        assert_eq!(status, hyper::StatusCode::BAD_REQUEST);
        assert_eq!(content_type, "text/plain");
        assert_eq!(body, "Bad Request");
    }

    #[tokio::test]
    async fn debug_ip_gets_the_details_as_html() {
        let connection_ip = ConnectionIp::Tcp("10.0.0.5:5000".parse().unwrap());

        let response = bad_request_response(
            true,
            &connection_ip,
            &request(),
            &listen_port_config(),
            BadRequestReason::NoConfigurationForHost("unknown.example.com"),
        );

        let (status, content_type, body) = read(response).await;

        assert_eq!(status, hyper::StatusCode::BAD_REQUEST);
        assert_eq!(content_type, "text/html; charset=utf-8");
        // The body is the html document alone — not a raw HTTP response.
        assert!(body.starts_with("<!DOCTYPE html>"), "{body}");
        assert!(body.contains("<h2>No configuration found</h2>"));
        assert!(body.contains("configured for host &#39;unknown.example.com&#39;"));
        assert!(body.contains("10.0.0.5 (listed in global_settings.debug_ip)"));
        assert!(body.contains("<tr><th>Uri</th><td>/some/path?a=1</td></tr>"));
        assert!(body.contains("<tr><th>Listening on</th><td>0.0.0.0:443</td></tr>"));
        assert!(body.contains("<tr><th>Type</th><td>Https2</td></tr>"));
        assert!(body.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
        assert!(!body.contains("<script>"));
    }

    #[tokio::test]
    async fn debug_ip_is_told_when_the_host_can_not_be_detected() {
        let connection_ip = ConnectionIp::Tcp("10.0.0.5:5000".parse().unwrap());
        let request = hyper::Request::builder().uri("/").body(()).unwrap();

        let response = bad_request_response(
            true,
            &connection_ip,
            &request,
            &listen_port_config(),
            BadRequestReason::HostNotDetected,
        );

        let (status, _, body) = read(response).await;

        assert_eq!(status, hyper::StatusCode::BAD_REQUEST);
        assert!(body.contains("<h2>Can not detect host</h2>"));
        assert!(body.contains("<tr><th>Host header</th><td>(none)</td></tr>"));
    }
}
