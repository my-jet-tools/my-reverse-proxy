use serde::*;

use super::*;

const HTTP1_ENDPOINT_TYPE: &str = "http";
const HTTP2_ENDPOINT_TYPE: &str = "http2";

const HTTPS1_ENDPOINT_TYPE: &str = "https";
const HTTPS2_ENDPOINT_TYPE: &str = "https2";

const TCP_ENDPOINT_TYPE: &str = "tcp";

const MCP_ENDPOINT_TYPE: &str = "mcp";

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct EndpointSettings {
    #[serde(rename = "type")]
    pub endpoint_type: String,
    pub ssl_certificate: Option<String>,
    pub client_certificate_ca: Option<String>,
    pub google_auth: Option<String>,
    /// Name of an `oauth:` block. When set, this endpoint also serves the OAuth
    /// 2.1 authorization-server endpoints and every proxied request on it has to
    /// carry an access token this proxy minted.
    pub oauth: Option<String>,
    pub modify_http_headers: Option<ModifyHttpHeadersSettings>,
    pub debug: Option<bool>,
    pub inject_country: Option<bool>,
    /// `true`: the hostname is proxied by Cloudflare, and nothing else may reach it - a
    /// connection is taken from the networks of Cloudflare only, and the client of a request is
    /// its `CF-Connecting-IP`. See [`crate::cloudflare`].
    pub cloudflare: Option<bool>,
    pub whitelisted_ip: Option<String>,
    /// The id of a list of `country_white_lists`: a client is served only from a country of it.
    /// Together with `whitelisted_ip` a client has to pass both.
    pub whitelisted_country: Option<String>,
    pub template_id: Option<String>,
    pub allowed_users: Option<String>,
    /// The id of a set of `api_keys:`: each location of the endpoint takes a request with a key
    /// of the set in `X-Api-Key` only. A location may name a set of its own, or `none`. `none`
    /// here takes away the one of the template. See [`crate::api_keys`].
    pub api_keys_auth: Option<String>,
    pub keep_alive: Option<bool>,
    pub track_metrics_by_all_domains: Option<bool>,
    pub hsts: Option<bool>,
    pub mcp_buffer_size: Option<String>,
    #[serde(flatten)]
    pub timeouts: TimeoutsSettings,
}

impl EndpointSettings {
    pub fn get_debug(&self) -> bool {
        self.debug.unwrap_or(false)
    }

    pub fn get_inject_country(&self) -> bool {
        self.inject_country.unwrap_or(false)
    }

    pub fn get_cloudflare(&self) -> bool {
        self.cloudflare.unwrap_or(false)
    }

    pub fn get_mcp_buffer_size(&self) -> usize {
        match &self.mcp_buffer_size {
            Some(buffer_size) => {
                super::parse_buffer_size(buffer_size).unwrap_or_else(|err| panic!("{}", err))
            }
            None => crate::consts::DEFAULT_MCP_BUFFER_SIZE,
        }
    }

    pub fn get_endpoint_type(&self) -> Result<EndpointTypeSettings, String> {
        let result = match self.endpoint_type.as_str() {
            HTTP1_ENDPOINT_TYPE => EndpointTypeSettings::Http1,
            HTTP2_ENDPOINT_TYPE => EndpointTypeSettings::Http2,
            HTTPS1_ENDPOINT_TYPE => EndpointTypeSettings::Https1,
            "http1" => EndpointTypeSettings::Https1,
            HTTPS2_ENDPOINT_TYPE => EndpointTypeSettings::Https2,
            TCP_ENDPOINT_TYPE => EndpointTypeSettings::Tcp,
            MCP_ENDPOINT_TYPE => EndpointTypeSettings::Mcp,
            _ => return Err(format!("Unknown endpoint type: '{}'", self.endpoint_type)),
        };

        Ok(result)
    }
}
