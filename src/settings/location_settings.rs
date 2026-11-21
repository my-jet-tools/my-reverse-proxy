use serde::*;

use super::*;

pub enum LocationType {
    Http,
    Http2,
    Https1,
    Https2,
    Files,
    StaticContent,
    UnixSocketHttp,
    UnixSocketHttp2,
    Mcp,
    McpH2,
    Drop,
    DynamicProxy,
}

impl LocationType {
    pub fn detect_from_location_settings(
        location_settings: &LocationSettings,
    ) -> Result<Self, String> {
        match location_settings.proxy_pass_to.as_ref() {
            Some(src) => {
                if src.eq_ignore_ascii_case("static") {
                    return Ok(Self::StaticContent);
                }

                if src.eq_ignore_ascii_case("drop") {
                    return Ok(Self::Drop);
                }

                if src.eq_ignore_ascii_case(crate::consts::location_type::DYNAMIC)
                    || src.eq_ignore_ascii_case("dynamic_proxy")
                {
                    return Ok(Self::DynamicProxy);
                }

                let mut splitted = src.split("->");

                let mut left_part = splitted.next().unwrap();

                if let Some(right_part) = splitted.next() {
                    left_part = right_part;
                }

                if left_part.starts_with("unix+http2") {
                    return Ok(Self::UnixSocketHttp2);
                };

                if left_part.starts_with("unix+http") {
                    return Ok(Self::UnixSocketHttp);
                };

                if left_part.starts_with("https") {
                    return Ok(Self::Https1);
                };

                if left_part.starts_with("http") {
                    return Ok(Self::Http);
                };

                Ok(Self::Files)
            }
            None => Ok(Self::StaticContent),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct LocationSettings {
    pub path: Option<String>,
    pub proxy_pass_to: Option<String>,
    #[serde(rename = "type")]
    pub location_type: Option<String>,
    pub domain_name: Option<String>,
    pub modify_http_headers: Option<ModifyHttpHeadersSettings>,
    pub default_file: Option<String>,
    pub status_code: Option<u16>,
    pub content_type: Option<String>,
    pub body: Option<String>,
    pub whitelisted_ip: Option<String>,
    /// The id of a list of `country_white_lists`: this location serves a client only from a
    /// country of it - on top of what the endpoint asks.
    pub whitelisted_country: Option<String>,
    pub compress: Option<bool>,
    pub trace_payload: Option<bool>,
    /// The id of a set of `api_keys:` this location takes requests with a key of in `X-Api-Key`
    /// only - in place of the one of its endpoint. `none` opens the location although its
    /// endpoint is guarded. See [`crate::api_keys`].
    pub api_keys_auth: Option<String>,
    /// Removed: `api_keys_auth` took its place. Read only to refuse the settings - a location
    /// with it left in would be open to everybody without a word.
    pub auth_header: Option<String>,
    pub allowed_hosts: Option<Vec<String>>,
    pub strip_path: Option<bool>,
    /// The requests one client may make to the location - `10/s`, `600/m`, `100/h` - on top of
    /// the `rate_limit` of its endpoint. Over it: `429`. See [`crate::types::RateLimiter`].
    pub rate_limit: Option<String>,
    /// The requests of `rate_limit` a client may make at once. Absent: the number of the rate.
    pub rate_limit_burst: Option<u32>,
    #[serde(flatten)]
    pub timeouts: TimeoutsSettings,
}

impl LocationSettings {
    pub fn get_location_type(&self) -> Result<Option<LocationType>, String> {
        use crate::consts::location_type::*;
        if let Some(location_type) = self.location_type.as_ref() {
            match location_type.as_str() {
                "unix+http" => Ok(LocationType::UnixSocketHttp.into()),
                "unix+http2" => Ok(LocationType::UnixSocketHttp2.into()),
                "http" => Ok(LocationType::Http.into()),
                "http2" => Ok(LocationType::Http2.into()),
                "https" => Ok(LocationType::Https1.into()),
                "https1" => Ok(LocationType::Https1.into()),
                "https2" => Ok(LocationType::Https2.into()),
                STATIC => Ok(LocationType::StaticContent.into()),
                MCP => Ok(LocationType::Mcp.into()),
                MCP_H2 => Ok(LocationType::McpH2.into()),
                "drop" => Ok(LocationType::Drop.into()),
                DYNAMIC | "dynamic_proxy" => Ok(LocationType::DynamicProxy.into()),
                _ => Err(format!("Unknown remote location type {}", location_type)),
            }
        } else {
            Ok(None)
        }
    }

    pub fn get_compress(&self) -> bool {
        self.compress.unwrap_or(false)
    }

    pub fn get_strip_path(&self) -> bool {
        self.strip_path.unwrap_or(false)
    }
}
