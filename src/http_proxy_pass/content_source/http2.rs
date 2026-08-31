use crate::{
    http_client_connectors::HttpConnector,
    http_proxy_pass::ProxyPassError,
    upstream_h2_pool::{ConnectorFactory, PoolDesc, PoolParams},
};

use super::*;

pub struct Http2ContentSource {
    pub pool_desc: PoolDesc,
    pub pool_params: PoolParams,
    pub factory: ConnectorFactory<HttpConnector>,
    pub request_timeout: std::time::Duration,
}

impl Http2ContentSource {
    pub async fn execute(
        &self,
        req: http::Request<http_body_util::Full<bytes::Bytes>>,
    ) -> Result<HttpResponse, ProxyPassError> {
        let pool = match crate::app::APP_CTX
            .h2_tcp_pools
            .get(self.pool_desc.location_id)
        {
            Some(p) => p,
            None => crate::app::APP_CTX.h2_tcp_pools.ensure_pool(
                self.pool_desc.clone(),
                self.pool_params.clone(),
                self.factory.clone(),
            ),
        };

        execute_pooled_h2(&pool, &self.pool_desc.name, req, self.request_timeout).await
    }

    /// Same upstream, but the request body is the client's own stream of frames —
    /// forwarded as it arrives, never collected. See
    /// [`execute_pooled_h2_streamed`] for what that costs (no failover).
    pub async fn execute_streamed(
        &self,
        req: hyper::Request<crate::my_http2_client::HyperRequestBody>,
        content_size: Option<usize>,
    ) -> Result<HttpResponse, ProxyPassError> {
        let pool = match crate::app::APP_CTX
            .h2_tcp_pools
            .get(self.pool_desc.location_id)
        {
            Some(p) => p,
            None => crate::app::APP_CTX.h2_tcp_pools.ensure_pool(
                self.pool_desc.clone(),
                self.pool_params.clone(),
                self.factory.clone(),
            ),
        };

        execute_pooled_h2_streamed(&pool, req, content_size, self.request_timeout).await
    }
}
