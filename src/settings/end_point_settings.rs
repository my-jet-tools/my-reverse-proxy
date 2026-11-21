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
    /// The headers, each with its one value, every request to the endpoint has to come with -
    /// a request without them closes its connection without a word. They never reach an
    /// upstream, and their values are never logged. See [`crate::required_headers`].
    pub request_with_header_only: Option<RequestWithHeaderOnlySettings>,
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
    /// The most of one request body the proxy holds in memory before it sends it on - to an
    /// upstream which takes a body in one piece. A larger body is answered `413`. Bytes, or a
    /// number with `Kb` / `Mb` / `Gb`. Absent: the one of `global_settings`. See
    /// [`crate::types::BufferedBodyLimits`].
    pub max_buffered_request_body: Option<String>,
    /// The most any request body to the endpoint may take - streamed to its upstream or held in
    /// memory: nginx's `client_max_body_size`. A body which says it is larger is answered `413`
    /// before anything goes upstream; one which comes larger is cut. Absent: the one of
    /// `global_settings`, else no limit.
    pub max_request_body: Option<String>,
    /// The oldest TLS a client may connect with: `1.2` or `1.3`. Absent: the one of
    /// `global_settings`, else `1.2`. See [`crate::types::TlsMinVersion`].
    #[serde(default, deserialize_with = "crate::types::number_or_text")]
    pub tls_min_version: Option<String>,
    /// The requests one client may make to the endpoint - `10/s`, `600/m`, `100/h` - every
    /// location of it together. Over it: `429`. See [`crate::types::RateLimiter`].
    pub rate_limit: Option<String>,
    /// The requests of `rate_limit` a client may make at once. Absent: the number of the rate.
    pub rate_limit_burst: Option<u32>,
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
