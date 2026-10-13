use std::sync::Arc;

use rust_extensions::remote_endpoint::RemoteEndpointOwned;

use crate::http_content_source::{FileRequestPath, RequestExecutorResult};
use crate::http_proxy_pass::ProxyPassError;

pub struct PathOverGatewayContentSource {
    pub gateway_id: Arc<String>,
    pub path: Arc<RemoteEndpointOwned>,
    pub default_file: Option<String>,
}

impl PathOverGatewayContentSource {
    pub async fn get_file(
        &self,
        path: &FileRequestPath<'_>,
    ) -> Result<RequestExecutorResult, ProxyPassError> {
        crate::http_proxy_pass::executors::get_file_from_gateway(
            self.gateway_id.as_str(),
            self.path.as_str(),
            self.default_file.as_deref(),
            path,
        )
        .await
    }
}
