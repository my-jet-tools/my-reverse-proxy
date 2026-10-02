use std::{sync::Arc, time::Duration};

use arc_swap::ArcSwapOption;
use hyper::Uri;
use my_http_server::WebContentType;
use my_ssh::SshSession;

use crate::http_proxy_pass::{content_source::HttpResponse, ProxyPassError};

use super::{RequestExecutor, RequestExecutorResult};

pub struct PathOverSshContentSource {
    ssh_session: Arc<SshSession>,
    home_value: Arc<ArcSwapOption<String>>,
    default_file: Option<String>,
    pub file_path: String,
    execute_timeout: Duration,
}

impl PathOverSshContentSource {
    pub fn new(
        ssh_session: Arc<SshSession>,
        file_path: String,
        default_file: Option<String>,
        execute_timeout: Duration,
    ) -> Self {
        Self {
            ssh_session,
            file_path,
            home_value: Arc::new(ArcSwapOption::empty()),
            default_file,
            execute_timeout,
        }
    }

    pub async fn get_request_executor(
        &self,
        uri: &Uri,
    ) -> Result<Arc<dyn RequestExecutor + Send + Sync + 'static>, ProxyPassError> {
        let file_path = if uri.path() == "/" {
            if let Some(default_file) = self.default_file.as_ref() {
                format!("{}/{}", self.file_path, default_file)
            } else {
                format!("{}{}", self.file_path, uri.path())
            }
        } else {
            format!("{}{}", self.file_path, uri.path())
        };

        let result = FileOverSshRequestExecutor {
            file_path,
            ssh_session: self.ssh_session.clone(),
            home_value: self.home_value.clone(),
            execute_timeout: self.execute_timeout,
        };
        Ok(Arc::new(result))
    }

    pub async fn execute(
        &self,
        req: http::Request<http_body_util::Full<bytes::Bytes>>,
    ) -> Result<HttpResponse, ProxyPassError> {
        let request_executor = self.get_request_executor(req.uri()).await?;
        let result = request_executor.execute_request().await?;
        Ok(HttpResponse::Response(result.into()))
    }
}

pub struct FileOverSshRequestExecutor {
    ssh_session: Arc<SshSession>,
    file_path: String,
    home_value: Arc<ArcSwapOption<String>>,
    execute_timeout: Duration,
}

#[async_trait::async_trait]
impl RequestExecutor for FileOverSshRequestExecutor {
    async fn execute_request(&self) -> Result<RequestExecutorResult, ProxyPassError> {
        let file_path = if self.file_path.contains("~") {
            let home_value = match self.home_value.load_full() {
                Some(value) => value,
                None => {
                    let (home, _, _) = self
                        .ssh_session
                        .execute_command("echo $HOME", self.execute_timeout)
                        .await?;
                    let value = Arc::new(String::from_utf8_lossy(&home).trim().to_string());
                    self.home_value.store(Some(value.clone()));
                    value
                }
            };

            self.file_path.replace("~", home_value.as_str())
        } else {
            self.file_path.clone()
        };

        let result = crate::scripts::ssh::download_remote_file(
            &self.ssh_session,
            &file_path,
            self.execute_timeout,
        )
        .await;

        match result {
            Ok(content) => Ok(RequestExecutorResult {
                status_code: 200,
                content_type: WebContentType::detect_by_extension(&file_path),
                body: content,
            }),
            Err(err) => {
                println!("{} -> Error: {:?}", file_path, err);
                if crate::scripts::ssh::is_remote_file_not_found(&err) {
                    return Ok(RequestExecutorResult {
                        status_code: 404,
                        content_type: None,
                        body: "Not found".as_bytes().to_vec(),
                    });
                }

                Err(ProxyPassError::SshSessionError(err))
            }
        }
    }
}
