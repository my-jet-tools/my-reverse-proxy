use std::{sync::Arc, time::Duration};

use my_http_server::WebContentType;
use my_ssh::{SshCredentials, SshSessionError};

use crate::http_proxy_pass::ProxyPassError;

use super::{FileRequestPath, RequestExecutorResult};

pub struct PathOverSshContentSource {
    ssh_credentials: Arc<SshCredentials>,
    /// The folder on the ssh host. A leading `~` stays as it is: it is the home directory of
    /// the ssh user there, and my-ssh expands it.
    files_path: String,
    default_file: Option<String>,
    execute_timeout: Duration,
}

impl PathOverSshContentSource {
    pub fn new(
        ssh_credentials: Arc<SshCredentials>,
        files_path: String,
        default_file: Option<String>,
        execute_timeout: Duration,
    ) -> Self {
        Self {
            ssh_credentials,
            files_path,
            default_file,
            execute_timeout,
        }
    }

    pub async fn get_file(
        &self,
        path: &FileRequestPath<'_>,
    ) -> Result<RequestExecutorResult, ProxyPassError> {
        let Some(file_path) = self.remote_file_path(path) else {
            return Ok(RequestExecutorResult::not_found());
        };

        // The session, the opening of the file and the reading of it get `execute_timeout`
        // each. my-ssh limits the last two itself. The session it waits for without a limit -
        // a host which takes the connection and then says nothing is waited for for good - so
        // it is the limit of the whole fetch which ends that wait: a request is answered, and
        // the connection of its client let go, whatever the host does.
        let fetch_timeout = 3 * self.execute_timeout;

        let result = tokio::time::timeout(fetch_timeout, self.fetch(&file_path))
            .await
            .unwrap_or(Err(SshSessionError::Timeout));

        match result {
            Ok(content) => Ok(RequestExecutorResult {
                status_code: 200,
                content_type: WebContentType::detect_by_extension(&file_path),
                body: content,
            }),
            Err(err) => {
                println!("{} -> Error: {:?}", file_path, err);
                if crate::scripts::ssh::is_remote_file_not_found(&err) {
                    return Ok(RequestExecutorResult::not_found());
                }

                Err(ProxyPassError::SshSessionError(err))
            }
        }
    }

    async fn fetch(&self, file_path: &str) -> Result<Vec<u8>, SshSessionError> {
        // Taken from the pool for every request: the pool replaces a session which died, and
        // one held here would stay dead.
        let ssh_session = crate::scripts::ssh::get_ssh_session(&self.ssh_credentials)
            .await
            .map_err(SshSessionError::Other)?;

        crate::scripts::ssh::download_remote_file(&ssh_session, file_path, self.execute_timeout)
            .await
    }

    fn remote_file_path(&self, path: &FileRequestPath<'_>) -> Option<String> {
        path.in_folder(&self.files_path, self.default_file.as_deref())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source(files_path: &str, default_file: Option<&str>) -> PathOverSshContentSource {
        let ssh_credentials = SshCredentials::SshAgent {
            ssh_remote_host: "127.0.0.1".to_string(),
            ssh_remote_port: 22,
            ssh_user_name: "user".to_string(),
        };

        PathOverSshContentSource::new(
            Arc::new(ssh_credentials),
            files_path.to_string(),
            default_file.map(|itm| itm.to_string()),
            Duration::from_secs(1),
        )
    }

    /// The home directory is the one of the ssh user on the remote host, so the `~` goes over
    /// as it is - and a `~` of the request path is a part of a name.
    #[test]
    fn the_folder_keeps_its_tilde_for_the_remote_host() {
        let source = source("~/web_content", Some("index.html"));

        let path = FileRequestPath::parse("/css/a.css").unwrap();
        assert_eq!(
            source.remote_file_path(&path).unwrap(),
            "~/web_content/css/a.css"
        );

        let path = FileRequestPath::parse("/~backup/a.css").unwrap();
        assert_eq!(
            source.remote_file_path(&path).unwrap(),
            "~/web_content/~backup/a.css"
        );

        let root = FileRequestPath::parse("/").unwrap();
        assert_eq!(
            source.remote_file_path(&root).unwrap(),
            "~/web_content/index.html"
        );
    }

    #[test]
    fn the_root_without_a_default_file_is_no_file() {
        let source = source("~/web_content", None);

        let root = FileRequestPath::parse("/").unwrap();
        assert_eq!(source.remote_file_path(&root), None);
    }

    /// An ssh host which takes the connection and then says nothing. my-ssh waits for such a
    /// session without a limit; a request for a file of the host is given up on all the same,
    /// once the session, the opening and the reading have had their time.
    #[tokio::test]
    async fn a_host_which_says_nothing_is_given_up_on() {
        const EXECUTE_TIMEOUT: Duration = Duration::from_millis(200);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        // Takes every connection and keeps it, without a word.
        let silent_host = tokio::spawn(async move {
            let mut connections = Vec::new();
            while let Ok((connection, _)) = listener.accept().await {
                connections.push(connection);
            }
        });

        let source = PathOverSshContentSource::new(
            Arc::new(SshCredentials::UserNameAndPassword {
                ssh_remote_host: "127.0.0.1".to_string(),
                ssh_remote_port: port,
                ssh_user_name: "user".to_string(),
                password: "password".to_string(),
            }),
            "~/web_content".to_string(),
            Some("index.html".to_string()),
            EXECUTE_TIMEOUT,
        );

        let path = FileRequestPath::parse("/index.html").unwrap();
        let asked = std::time::Instant::now();

        let result = tokio::time::timeout(Duration::from_secs(20), source.get_file(&path))
            .await
            .expect("the request waits for the host for good");

        assert!(
            matches!(
                result,
                Err(ProxyPassError::SshSessionError(SshSessionError::Timeout))
            ),
            "{:?}",
            result.map(|file| file.status_code)
        );
        assert!(asked.elapsed() >= 3 * EXECUTE_TIMEOUT);

        silent_host.abort();
    }
}
