use std::time::Duration;

use bytes::Bytes;
use http_body_util::Full;

use crate::configurations::{MyReverseProxyRemoteEndpoint, ProxyPassFilesPathModel};
use crate::http_proxy_pass::{
    content_source::{HttpResponse, PathOverGatewayContentSource},
    ProxyPassError,
};

use super::{
    local_path::LocalPathContentSrc, FileRequestPath, PathOverSshContentSource,
    RequestExecutorResult,
};

/// The folder of a files location, wherever it is: local, behind ssh or behind a gateway. The
/// hyper path (`http2` and `https2` endpoints) and the h1 pipeline (`http` and `https`
/// endpoints) both serve a files location from here.
pub enum FilesContentSource {
    Local(LocalPathContentSrc),
    OverSsh(PathOverSshContentSource),
    OverGateway(PathOverGatewayContentSource),
}

impl FilesContentSource {
    /// Nothing is connected here: a source is a few `Arc` clones.
    pub fn new(model: &ProxyPassFilesPathModel, ssh_timeout: Duration) -> Self {
        match &model.files_path {
            MyReverseProxyRemoteEndpoint::Gateway { id, remote_host } => {
                Self::OverGateway(PathOverGatewayContentSource {
                    gateway_id: id.clone(),
                    path: remote_host.clone(),
                    default_file: model.default_file.clone(),
                })
            }
            MyReverseProxyRemoteEndpoint::OverSsh {
                ssh_credentials,
                remote_host,
            } => Self::OverSsh(PathOverSshContentSource::new(
                ssh_credentials.clone(),
                remote_host.as_str().to_string(),
                model.default_file.clone(),
                ssh_timeout,
            )),
            MyReverseProxyRemoteEndpoint::Direct { remote_host } => Self::Local(
                LocalPathContentSrc::new(remote_host.as_str(), model.default_file.clone()),
            ),
        }
    }

    /// - `Ok` with 200: the file;
    /// - `Ok` with 404: no such file in a local or an ssh folder, or the root is asked for and
    ///   there is no default file;
    /// - `Err(NoLocationFound)`: no such file behind a gateway;
    /// - any other `Err`: the file could not be asked for - the gateway is not connected, the
    ///   ssh host can not be reached or does not let the file be read.
    pub async fn get_file(
        &self,
        path: &FileRequestPath<'_>,
    ) -> Result<RequestExecutorResult, ProxyPassError> {
        match self {
            Self::Local(source) => source.get_file(path).await,
            Self::OverSsh(source) => source.get_file(path).await,
            Self::OverGateway(source) => source.get_file(path).await,
        }
    }

    /// The hyper path. hyper has already cut the query string off the path.
    ///
    /// A path which does not pass the check is answered 400 as an ordinary response, not as an
    /// error: an error is written to the location log - for every scanner which comes by - and
    /// there is none which is answered 400.
    pub async fn execute(
        &self,
        req: hyper::Request<Full<Bytes>>,
    ) -> Result<HttpResponse, ProxyPassError> {
        let result = match FileRequestPath::parse(req.uri().path()) {
            Ok(path) => self.get_file(&path).await?,
            Err(_) => RequestExecutorResult::bad_request(),
        };

        Ok(HttpResponse::Response(result.into()))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use http_body_util::BodyExt;
    use my_ssh::SshCredentials;

    use super::super::test_utils::*;
    use super::*;
    use crate::settings_compiled::SettingsCompiled;

    const SSH_TIMEOUT: Duration = Duration::from_secs(2);

    /// The source of a location whose `proxy_pass_to` is `files_path`, made the way the
    /// settings are compiled.
    async fn source_of(files_path: &str, default_file: Option<&str>) -> FilesContentSource {
        let model = ProxyPassFilesPathModel {
            files_path: MyReverseProxyRemoteEndpoint::try_parse(
                files_path,
                &SettingsCompiled::default(),
            )
            .await
            .unwrap(),
            default_file: default_file.map(|itm| itm.to_string()),
        };

        FilesContentSource::new(&model, SSH_TIMEOUT)
    }

    async fn get_file(source: &FilesContentSource, path: &str) -> RequestExecutorResult {
        let path = FileRequestPath::parse(path).unwrap();
        source.get_file(&path).await.unwrap()
    }

    /// A request through the hyper entry: status, content type and body of the response.
    async fn execute(source: &FilesContentSource, uri: &str) -> (u16, Option<String>, Vec<u8>) {
        let request = hyper::Request::builder()
            .uri(uri)
            .body(Full::new(Bytes::new()))
            .unwrap();

        let HttpResponse::Response(response) = source.execute(request).await.unwrap() else {
            panic!("a files location answered with a websocket upgrade");
        };

        let status = response.status().as_u16();
        let content_type = response
            .headers()
            .get(hyper::header::CONTENT_TYPE)
            .map(|value| value.to_str().unwrap().to_string());
        let body = response.into_body().collect().await.unwrap().to_bytes();

        (status, content_type, body.to_vec())
    }

    #[tokio::test]
    async fn the_folder_decides_where_the_files_come_from() {
        let source = source_of("/srv/www", None).await;
        assert!(matches!(source, FilesContentSource::Local(_)));

        let source = source_of("gateway:gw->/srv/www", None).await;
        assert!(matches!(source, FilesContentSource::OverGateway(_)));

        let source = source_of("ssh:user@10.0.0.5:22->~/web_content", None).await;
        assert!(matches!(source, FilesContentSource::OverSsh(_)));
    }

    #[tokio::test]
    async fn a_file_is_served_with_its_content_type() {
        let site = TestSite::new();
        let source = source_of(&site.root(), None).await;

        let file = get_file(&source, "/index.html").await;
        assert_eq!(file.status_code, 200);
        assert_eq!(file.content_type.unwrap().as_str(), "text/html");
        assert_eq!(file.body, INDEX_HTML);

        let file = get_file(&source, "/css/site.css").await;
        assert_eq!(file.status_code, 200);
        assert_eq!(file.content_type.unwrap().as_str(), "text/css");
        assert_eq!(file.body, SITE_CSS);
    }

    #[tokio::test]
    async fn the_default_file_is_served_for_the_root() {
        let site = TestSite::new();

        let source = source_of(&site.root(), Some("index.html")).await;
        let file = get_file(&source, "/").await;
        assert_eq!(file.status_code, 200);
        assert_eq!(file.content_type.unwrap().as_str(), "text/html");
        assert_eq!(file.body, INDEX_HTML);

        // For the root only: a folder inside has no default file - also when a file of that
        // name is in it.
        std::fs::write(format!("{}/css/index.html", site.root()), b"inner").unwrap();
        assert_eq!(get_file(&source, "/css/").await.status_code, 404);
        assert_eq!(get_file(&source, "/css").await.status_code, 404);

        let source = source_of(&site.root(), None).await;
        let file = get_file(&source, "/").await;
        assert_eq!(file.status_code, 404);
        assert_eq!(file.body, b"Not found");
    }

    #[tokio::test]
    async fn a_missing_file_and_a_directory_are_not_found() {
        let site = TestSite::new();
        let source = source_of(&site.root(), Some("index.html")).await;

        for path in [
            "/missing.html",
            "/css",
            "/css/",
            "/css/missing.css",
            // The slash is not cut off: a file is not a folder.
            "/index.html/",
        ] {
            let file = get_file(&source, path).await;
            assert_eq!(file.status_code, 404, "{path}");
            assert!(file.content_type.is_none(), "{path}");
        }
    }

    /// A segment which changes nothing would be another path to the same file: it is refused,
    /// and a file is served under one path only.
    #[tokio::test]
    async fn a_dot_segment_and_an_empty_one_are_refused() {
        let site = TestSite::new();
        let source = source_of(&site.root(), None).await;

        // The file system would take each of them for the file.
        assert!(std::fs::read(format!("{}//index.html", site.root())).is_ok());
        assert!(std::fs::read(format!("{}/./index.html", site.root())).is_ok());

        for path in [
            "/./index.html",
            "//index.html",
            "/css/./site.css",
            "/css//site.css",
        ] {
            let (status, _, body) = execute(&source, path).await;
            assert_eq!(status, 400, "{path}");
            assert_eq!(body, b"Bad Request", "{path}");
        }

        assert_eq!(get_file(&source, "/index.html").await.status_code, 200);
        assert_eq!(get_file(&source, "/css/site.css").await.status_code, 200);
    }

    /// A file is looked up by the name as it was received.
    #[tokio::test]
    async fn a_file_name_is_not_decoded() {
        let site = TestSite::new();
        std::fs::write(format!("{}/file%20name.txt", site.root()), b"named").unwrap();
        let source = source_of(&site.root(), None).await;

        let file = get_file(&source, "/file%20name.txt").await;
        assert_eq!(file.status_code, 200);
        assert_eq!(file.body, b"named");

        assert_eq!(get_file(&source, "/index%2ehtml").await.status_code, 404);

        // Encoded twice, `..` passes the check - as a name, which is not there.
        assert_eq!(
            get_file(&source, "/%252e%252e/secret.txt")
                .await
                .status_code,
            404
        );
    }

    #[tokio::test]
    async fn a_path_out_of_the_folder_is_refused_on_the_hyper_path() {
        let site = TestSite::new();
        let source = source_of(&site.root(), Some("index.html")).await;

        // What the folder glued to the path as it is would read.
        assert_eq!(
            std::fs::read(format!("{}/../secret.txt", site.root())).unwrap(),
            SECRET
        );

        for uri in [
            "/../secret.txt",
            "/css/../../secret.txt",
            "/%2e%2e/secret.txt",
            "/%2E%2E/secret.txt",
            "/.%2e/secret.txt",
            "/..%2fsecret.txt",
            "/..%5csecret.txt",
            "/..\\secret.txt",
            "/../secret.txt?v=1",
            "http://localhost/../secret.txt",
        ] {
            let (status, content_type, body) = execute(&source, uri).await;
            assert_eq!(status, 400, "{uri}");
            assert_eq!(
                content_type.as_deref(),
                Some("text/plain; charset=utf-8"),
                "{uri}"
            );
            assert_eq!(body, b"Bad Request", "{uri}");
        }
    }

    #[tokio::test]
    async fn the_query_string_is_not_a_part_of_the_file_name_on_the_hyper_path() {
        let site = TestSite::new();
        let source = source_of(&site.root(), Some("index.html")).await;

        let (status, content_type, body) = execute(&source, "/index.html?v=1").await;
        assert_eq!(status, 200);
        assert_eq!(content_type.as_deref(), Some("text/html"));
        assert_eq!(body, INDEX_HTML);

        let (status, _, body) = execute(&source, "/?utm=x").await;
        assert_eq!(status, 200);
        assert_eq!(body, INDEX_HTML);

        // The uri of a request over h2 is an absolute one.
        let (status, _, body) = execute(&source, "http://localhost/css/site.css?v=1").await;
        assert_eq!(status, 200);
        assert_eq!(body, SITE_CSS);

        let (status, content_type, body) = execute(&source, "/missing.html").await;
        assert_eq!(status, 404);
        assert_eq!(content_type, None);
        assert_eq!(body, b"Not found");
    }

    /// The method is not looked at on this path - it was not before either.
    #[tokio::test]
    async fn any_method_gets_the_file_on_the_hyper_path() {
        let site = TestSite::new();
        let source = source_of(&site.root(), None).await;

        let request = hyper::Request::builder()
            .method(hyper::Method::POST)
            .uri("/index.html")
            .body(Full::new(Bytes::from_static(b"a body")))
            .unwrap();

        let HttpResponse::Response(response) = source.execute(request).await.unwrap() else {
            panic!("a files location answered with a websocket upgrade");
        };
        assert_eq!(response.status().as_u16(), 200);
    }

    /// A folder which is not there is not the root of the file system.
    #[tokio::test]
    async fn an_empty_folder_serves_nothing() {
        let source = FilesContentSource::Local(LocalPathContentSrc::new("", None));
        assert_eq!(get_file(&source, "/etc/hosts").await.status_code, 404);

        let source =
            FilesContentSource::Local(LocalPathContentSrc::new("", Some("etc/hosts".to_string())));
        assert_eq!(get_file(&source, "/").await.status_code, 404);

        // What the request would have read otherwise.
        assert!(std::fs::read("/etc/hosts").is_ok());
    }

    /// No gateway is connected in the tests: `gw` is an id nothing answers to.
    #[tokio::test]
    async fn the_path_is_checked_before_a_gateway_is_asked() {
        let source = source_of("gateway:gw->/srv/www", Some("index.html")).await;

        let (status, _, body) = execute(&source, "/../secret.txt").await;
        assert_eq!(status, 400);
        assert_eq!(body, b"Bad Request");

        let path = FileRequestPath::parse("/index.html").unwrap();
        assert!(matches!(
            source.get_file(&path).await,
            Err(ProxyPassError::GatewayError)
        ));

        let request = hyper::Request::builder()
            .uri("/index.html")
            .body(Full::new(Bytes::new()))
            .unwrap();
        assert!(matches!(
            source.execute(request).await,
            Err(ProxyPassError::GatewayError)
        ));
    }

    /// The ssh host of these credentials is a listener of the test: nobody connects to it,
    /// and no session is taken from the pool.
    #[tokio::test]
    async fn the_path_is_checked_before_an_ssh_session_is_taken() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let source = source_of(
            &format!("ssh:user@127.0.0.1:{port}->~/web_content"),
            Some("index.html"),
        )
        .await;

        for uri in ["/../secret.txt", "/%2e%2e/secret.txt", "/..%2fsecret.txt"] {
            let (status, _, body) = execute(&source, uri).await;
            assert_eq!(status, 400, "{uri}");
            assert_eq!(body, b"Bad Request", "{uri}");
        }

        let FilesContentSource::OverSsh(_) = &source else {
            panic!("not an ssh source");
        };

        let ssh_credentials = SshCredentials::SshAgent {
            ssh_remote_host: "127.0.0.1".to_string(),
            ssh_remote_port: port,
            ssh_user_name: "user".to_string(),
        };
        assert!(my_ssh::SSH_SESSIONS_POOL
            .get(&ssh_credentials)
            .await
            .is_none());

        let connected = tokio::time::timeout(Duration::from_millis(200), listener.accept()).await;
        assert!(connected.is_err(), "the ssh host was connected to");
    }

    /// A host which does not answer is an error - not a file which is missing. The session is
    /// taken from the pool for the request.
    #[tokio::test]
    async fn an_ssh_host_which_can_not_be_reached_is_an_error() {
        let closed_port = {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            listener.local_addr().unwrap().port()
        };

        let ssh_credentials = Arc::new(SshCredentials::UserNameAndPassword {
            ssh_remote_host: "127.0.0.1".to_string(),
            ssh_remote_port: closed_port,
            ssh_user_name: "user".to_string(),
            password: "password".to_string(),
        });

        let source_with = |default_file: Option<&str>| {
            FilesContentSource::OverSsh(PathOverSshContentSource::new(
                ssh_credentials.clone(),
                "~/web_content".to_string(),
                default_file.map(|itm| itm.to_string()),
                SSH_TIMEOUT,
            ))
        };

        // The root without a default file is answered without the host.
        assert_eq!(get_file(&source_with(None), "/").await.status_code, 404);
        assert!(my_ssh::SSH_SESSIONS_POOL
            .get(&ssh_credentials)
            .await
            .is_none());

        let source = source_with(Some("index.html"));

        for path in ["/index.html", "/"] {
            let path = FileRequestPath::parse(path).unwrap();
            let result = tokio::time::timeout(Duration::from_secs(10), source.get_file(&path))
                .await
                .expect("a connection to a closed port is refused at once");

            assert!(matches!(result, Err(ProxyPassError::SshSessionError(_))));
        }

        assert!(my_ssh::SSH_SESSIONS_POOL
            .get(&ssh_credentials)
            .await
            .is_some());
    }
}
