use my_http_server::WebContentType;

use crate::http_content_source::{FileRequestPath, RequestExecutorResult};
use crate::http_proxy_pass::ProxyPassError;

pub struct LocalPathContentSrc {
    /// The folder, a leading `~` expanded.
    files_path: String,
    default_file: Option<String>,
}

impl LocalPathContentSrc {
    /// It is made for every request, so it does not fail: when the home directory is not known -
    /// the process does not start without one - the folder is kept as it is, and nothing is found
    /// in it.
    pub fn new(files_path: &str, default_file: Option<String>) -> Self {
        Self {
            files_path: crate::settings::expand_home(files_path)
                .unwrap_or_else(|_| files_path.to_string()),
            default_file,
        }
    }

    pub async fn get_file(
        &self,
        path: &FileRequestPath<'_>,
    ) -> Result<RequestExecutorResult, ProxyPassError> {
        let Some(file_path) = path.in_folder(&self.files_path, self.default_file.as_deref()) else {
            return Ok(RequestExecutorResult::not_found());
        };

        let result = match tokio::fs::read(&file_path).await {
            Ok(content) => RequestExecutorResult {
                status_code: 200,
                content_type: WebContentType::detect_by_extension(&file_path),
                body: content,
            },
            Err(_) => RequestExecutorResult::not_found(),
        };

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_leading_tilde_of_the_folder_is_the_home_directory() {
        let home = crate::settings::home_dir().unwrap();

        let source = LocalPathContentSrc::new("~/web_content", None);
        assert_eq!(source.files_path, format!("{}/web_content", home));

        let source = LocalPathContentSrc::new("/srv/~web_content", None);
        assert_eq!(source.files_path, "/srv/~web_content");
    }
}
