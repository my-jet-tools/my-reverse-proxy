use bytes::Bytes;
use http_body_util::{combinators::BoxBody, BodyExt};
use my_http_server::WebContentType;

use crate::http_proxy_pass::ProxyPassError;

pub struct RequestExecutorResult {
    pub status_code: u16,
    pub content_type: Option<WebContentType>,
    pub body: Vec<u8>,
}

impl From<RequestExecutorResult> for hyper::Response<BoxBody<Bytes, String>> {
    fn from(val: RequestExecutorResult) -> Self {
        let mut builder = hyper::Response::builder().status(val.status_code);

        if let Some(content_type) = val.content_type {
            builder = builder.header("Content-Type", content_type.as_str());
        }

        let full_body = http_body_util::Full::new(hyper::body::Bytes::from(val.body));
        builder
            .body(full_body.map_err(crate::to_hyper_error).boxed())
            .unwrap()
    }
}
#[async_trait::async_trait]
pub trait RequestExecutor {
    async fn execute_request(&self) -> Result<RequestExecutorResult, ProxyPassError>;
}
