use crate::error_templates as tpl;
use crate::h1_utils::Http1ResponseBuilder;
use crate::http_content_source::{FileRequestPath, FilesContentSource, RequestExecutorResult};
use crate::http_proxy_pass::ProxyPassError;

/// The answer to a request for a files location: a whole response, ready to be
/// written to the client.
pub struct FilesAnswer {
    pub bytes: Vec<u8>,
    /// `Some((status, failure))` when `bytes` is a 5xx page — the caller records
    /// it in the proxy logs, as every 5xx page returned to a client is.
    pub returned_5xx: Option<(u16, String)>,
}

impl FilesAnswer {
    fn page(page: &[u8]) -> Self {
        Self {
            bytes: page.to_vec(),
            returned_5xx: None,
        }
    }

    /// What the source came back with for `path`, as a response.
    /// `response_headers`: what `modify_http_headers` add to a response - they go on a file
    /// which is served, not on an error page.
    fn of_file(
        path: &FileRequestPath<'_>,
        file: Result<RequestExecutorResult, ProxyPassError>,
        response_headers: &[(String, String)],
    ) -> Self {
        match file {
            Ok(file) if file.status_code == 404 => Self::page(tpl::NOT_FOUND.as_slice()),
            Ok(file) => {
                let mut builder = Http1ResponseBuilder::new(file.status_code);
                if let Some(content_type) = file.content_type.as_ref() {
                    builder = builder.add_content_type(content_type.as_str());
                }
                for (name, value) in response_headers {
                    builder = builder.add_header(name, value);
                }
                Self {
                    bytes: builder.build_with_body(&file.body),
                    returned_5xx: None,
                }
            }
            // A file which is not there behind a gateway.
            Err(ProxyPassError::NoLocationFound) => Self::page(tpl::NOT_FOUND.as_slice()),
            // The gateway or the ssh host could not be reached: it is not the
            // file which is missing, so this is not a 404.
            Err(err) => Self {
                bytes: tpl::REMOTE_RESOURCE_IS_NOT_AVAILABLE.to_vec(),
                returned_5xx: Some((
                    503,
                    format!(
                        "can not get the file {}: {:?}",
                        crate::types::path_for_log(path.as_str()),
                        err
                    ),
                )),
            },
        }
    }
}

/// Answers a request for a files location (README "Serving the folder with
/// files") on the h1 path. `path` is the request path as received, without the
/// query string: the request path picks the file, `default_file` is served for
/// the root.
pub async fn answer_files_request(
    source: &FilesContentSource,
    method: &str,
    path: &str,
    response_headers: &[(String, String)],
) -> FilesAnswer {
    // Before the method rule: a path which does not pass the check is refused
    // whatever the method is.
    let Ok(path) = FileRequestPath::parse(path) else {
        return FilesAnswer::page(tpl::BAD_REQUEST.as_slice());
    };

    // Only GET and HEAD are served on this path. A HEAD is answered as the GET
    // would be: the caller sends the head of the response and leaves the body out.
    if method != "GET" && method != "HEAD" {
        return FilesAnswer::page(tpl::NOT_FOUND.as_slice());
    }

    FilesAnswer::of_file(&path, source.get_file(&path).await, response_headers)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::configurations::{MyReverseProxyRemoteEndpoint, ProxyPassFilesPathModel};
    use crate::http_content_source::test_utils::*;

    fn source_of(files_path: MyReverseProxyRemoteEndpoint) -> FilesContentSource {
        let model = ProxyPassFilesPathModel {
            files_path,
            default_file: Some("index.html".to_string()),
        };

        FilesContentSource::new(&model, Duration::from_secs(1))
    }

    fn local(site: &TestSite) -> FilesContentSource {
        source_of(MyReverseProxyRemoteEndpoint::Direct {
            remote_host: rust_extensions::remote_endpoint::RemoteEndpointOwned::try_parse(
                site.root(),
            )
            .unwrap()
            .into(),
        })
    }

    /// No gateway is connected in the tests: `gw` is an id nothing answers to.
    fn behind_unknown_gateway() -> FilesContentSource {
        source_of(
            MyReverseProxyRemoteEndpoint::try_parse_gateway_source("gateway:gw->/srv/www").unwrap(),
        )
    }

    fn response(head: &str, body: &[u8]) -> Vec<u8> {
        let mut result = head.as_bytes().to_vec();
        result.extend_from_slice(body);
        result
    }

    /// What `modify_http_headers` add to a response goes on a file which is served, and not on
    /// the page of a file which is not there.
    #[tokio::test]
    async fn the_response_headers_of_the_location_go_on_a_served_file() {
        let site = TestSite::new();
        let headers = [("x-frame-options".to_string(), "DENY".to_string())];

        let answer = answer_files_request(&local(&site), "GET", "/css/site.css", &headers).await;
        let head = String::from_utf8_lossy(&answer.bytes).to_string();
        assert!(head.starts_with("HTTP/1.1 200"), "{head}");
        assert!(head.contains("x-frame-options: DENY\r\n"), "{head}");

        let answer = answer_files_request(&local(&site), "GET", "/missing.css", &headers).await;
        let head = String::from_utf8_lossy(&answer.bytes).to_string();
        assert!(head.starts_with("HTTP/1.1 404"), "{head}");
        assert!(!head.contains("x-frame-options"), "{head}");
    }

    #[tokio::test]
    async fn a_file_is_a_whole_response_with_its_type_and_length() {
        let site = TestSite::new();

        let answer = answer_files_request(&local(&site), "GET", "/css/site.css", &[]).await;

        assert_eq!(
            answer.bytes,
            response(
                &format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: text/css\r\ncontent-length: {}\r\n\r\n",
                    SITE_CSS.len()
                ),
                SITE_CSS
            )
        );
        assert!(answer.returned_5xx.is_none());
    }

    #[tokio::test]
    async fn the_default_file_is_served_for_the_root() {
        let site = TestSite::new();

        let answer = answer_files_request(&local(&site), "GET", "/", &[]).await;

        assert_eq!(
            answer.bytes,
            response(
                &format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: text/html\r\ncontent-length: {}\r\n\r\n",
                    INDEX_HTML.len()
                ),
                INDEX_HTML
            )
        );
    }

    /// The content type comes from the extension; a file with another one goes
    /// without the header.
    #[tokio::test]
    async fn a_file_of_an_unknown_type_has_no_content_type() {
        let site = TestSite::new();
        std::fs::write(format!("{}/notes.bin", site.root()), b"notes").unwrap();

        let answer = answer_files_request(&local(&site), "GET", "/notes.bin", &[]).await;

        assert_eq!(
            answer.bytes,
            response("HTTP/1.1 200 OK\r\ncontent-length: 5\r\n\r\n", b"notes")
        );
    }

    /// The path is checked before the method is looked at, so a path out of the
    /// folder is a 400 whatever the method is.
    #[tokio::test]
    async fn a_path_out_of_the_folder_is_a_bad_request_for_any_method() {
        let site = TestSite::new();
        let source = local(&site);

        for method in ["GET", "POST", "HEAD", "DELETE"] {
            for path in [
                "/../secret.txt",
                "/%2e%2e/secret.txt",
                "/..%2fsecret.txt",
                "/a%00.html",
                "index.html",
            ] {
                let answer = answer_files_request(&source, method, path, &[]).await;

                assert_eq!(answer.bytes, tpl::BAD_REQUEST.as_slice(), "{method} {path}");
                assert!(answer.returned_5xx.is_none());
            }
        }

        assert!(tpl::BAD_REQUEST.starts_with(b"HTTP/1.1 400 Bad Request\r\ncontent-length: "));
    }

    #[tokio::test]
    async fn only_get_and_head_are_served() {
        let site = TestSite::new();
        let source = local(&site);

        for method in ["POST", "PUT", "DELETE", "OPTIONS"] {
            let answer = answer_files_request(&source, method, "/index.html", &[]).await;

            assert_eq!(answer.bytes, tpl::NOT_FOUND.as_slice(), "{method}");
            assert!(answer.returned_5xx.is_none());
        }

        // A HEAD is answered as the GET is: it is the caller which leaves the body out.
        let get = answer_files_request(&source, "GET", "/index.html", &[]).await;
        let head = answer_files_request(&source, "HEAD", "/index.html", &[]).await;
        assert!(get.bytes.starts_with(b"HTTP/1.1 200"));
        assert_eq!(head.bytes, get.bytes);
    }

    #[tokio::test]
    async fn a_missing_file_is_not_found() {
        let site = TestSite::new();
        let source = local(&site);

        for path in ["/missing.html", "/css", "/css/"] {
            let answer = answer_files_request(&source, "GET", path, &[]).await;

            assert_eq!(answer.bytes, tpl::NOT_FOUND.as_slice(), "{path}");
            assert!(answer.returned_5xx.is_none());
        }
    }

    /// A gateway which is not there is not a missing file: the client gets the
    /// 503 page, and the caller gets what to write to the proxy logs.
    #[tokio::test]
    async fn a_gateway_which_can_not_be_reached_is_a_logged_503() {
        let source = behind_unknown_gateway();

        let answer = answer_files_request(&source, "GET", "/index.html", &[]).await;

        assert_eq!(
            answer.bytes,
            tpl::REMOTE_RESOURCE_IS_NOT_AVAILABLE.as_slice()
        );
        assert_eq!(
            answer.returned_5xx,
            Some((
                503,
                "can not get the file \"/index.html\": GatewayError".to_string()
            ))
        );
    }

    /// A file which is not there comes back from a gateway as an error of its
    /// own, and from an ssh host which can not be reached comes any other one.
    #[test]
    fn a_file_missing_behind_a_gateway_is_not_found_and_a_failure_is_a_503() {
        let path = FileRequestPath::parse("/missing.html").unwrap();

        let answer = FilesAnswer::of_file(&path, Err(ProxyPassError::NoLocationFound), &[]);
        assert_eq!(answer.bytes, tpl::NOT_FOUND.as_slice());
        assert!(answer.returned_5xx.is_none());

        let answer = FilesAnswer::of_file(
            &path,
            Err(ProxyPassError::SshSessionError(
                my_ssh::SshSessionError::Timeout,
            )),
            &[],
        );
        assert_eq!(
            answer.bytes,
            tpl::REMOTE_RESOURCE_IS_NOT_AVAILABLE.as_slice()
        );
        assert_eq!(
            answer.returned_5xx,
            Some((
                503,
                "can not get the file \"/missing.html\": SshSessionError(Timeout)".to_string()
            ))
        );
    }

    /// The path is checked, and the method is, before the gateway is asked.
    #[tokio::test]
    async fn a_refused_request_does_not_get_to_the_gateway() {
        let source = behind_unknown_gateway();

        let answer = answer_files_request(&source, "GET", "/../secret.txt", &[]).await;
        assert_eq!(answer.bytes, tpl::BAD_REQUEST.as_slice());
        assert!(answer.returned_5xx.is_none());

        let answer = answer_files_request(&source, "POST", "/index.html", &[]).await;
        assert_eq!(answer.bytes, tpl::NOT_FOUND.as_slice());
        assert!(answer.returned_5xx.is_none());
    }
}
