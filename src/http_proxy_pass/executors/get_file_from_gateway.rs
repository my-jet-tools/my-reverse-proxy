use my_http_server::WebContentType;

use crate::{
    http_content_source::{FileRequestPath, RequestExecutorResult},
    http_proxy_pass::*,
    tcp_gateway::{FileRequestError, TcpGatewayConnection},
};

pub async fn get_file_from_gateway(
    gateway_id: &str,
    files_path: &str,
    default_file: Option<&str>,
    path: &FileRequestPath<'_>,
) -> Result<RequestExecutorResult, ProxyPassError> {
    let Some(gateway) = crate::app::APP_CTX.get_gateway_by_id(gateway_id) else {
        return Err(ProxyPassError::GatewayError);
    };

    get_file_from_gateway_connection(&gateway, files_path, default_file, path).await
}

/// The file `path` means inside `files_path`, a folder on the other end of `gateway`. The other
/// end reads whatever path it is sent: the folder and the checked path are put together here.
pub async fn get_file_from_gateway_connection(
    gateway: &TcpGatewayConnection,
    files_path: &str,
    default_file: Option<&str>,
    path: &FileRequestPath<'_>,
) -> Result<RequestExecutorResult, ProxyPassError> {
    let Some(full_path) = path.in_folder(files_path, default_file) else {
        return Ok(RequestExecutorResult::not_found());
    };

    match gateway.request_file(full_path.as_str()).await {
        Ok(content) => Ok(RequestExecutorResult {
            status_code: 200,
            content_type: WebContentType::detect_by_extension(full_path.as_str()),
            body: content,
        }),
        Err(err) => match err {
            FileRequestError::FileNotFound => Err(ProxyPassError::NoLocationFound),
            FileRequestError::GatewayDisconnected | FileRequestError::Timeout => {
                Err(ProxyPassError::GatewayError)
            }
        },
    }
}
