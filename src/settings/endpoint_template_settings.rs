use serde::*;

use super::ModifyHttpHeadersSettings;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct EndpointTemplateSettings {
    pub ssl_certificate: Option<String>,
    pub client_certificate_ca: Option<String>,
    pub google_auth: Option<String>,
    pub oauth: Option<String>,
    pub modify_http_headers: Option<ModifyHttpHeadersSettings>,
    pub whitelisted_ip: Option<String>,
    /// `api_keys_auth` of the endpoints of the template - an endpoint's own one takes its place.
    pub api_keys_auth: Option<String>,
}
