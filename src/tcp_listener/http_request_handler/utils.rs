use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};

use crate::http_proxy_pass::ProxyPassError;

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
