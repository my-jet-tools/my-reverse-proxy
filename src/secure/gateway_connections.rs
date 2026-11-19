use serde::Deserialize;

use super::StoredGatewayConnection;

/// A connection to a gateway as a call of the encrypted API or of MCP sets it: what an entry of
/// `gateway_clients` of the settings says, with the handshake signed by a private key of the
/// secure store. The fields are named as there.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayConnectionInput {
    /// The gateway id: what the routes name, `gateway:<id>->...`.
    pub id: String,
    /// `host:port` of the gateway server.
    pub remote_host: String,
    /// The id of the private key of the store the handshake is signed with.
    pub private_key: String,
    /// The compression level: 0 or nothing - off.
    pub compress: Option<u64>,
    /// The connect timeout in milliseconds; nothing - the default one.
    pub connect_timeout: Option<u64>,
    pub allow_incoming_forward_connections: Option<bool>,
    pub sync_ssl_certificates: Option<Vec<String>>,
    pub debug: Option<bool>,
}

impl GatewayConnectionInput {
    /// What the store keeps, or why the call is refused. Whether the private key is in the store
    /// is checked where the store is written.
    pub fn check(self) -> Result<StoredGatewayConnection, String> {
        let id = check_gateway_connection_id(&self.id)?.to_string();
        let remote_host = check_remote_host(&self.remote_host)?.to_string();

        let private_key = super::check_private_key_id(&self.private_key)
            .map_err(|err| format!("private_key: {err}"))?
            .to_string();

        let compress = match self.compress {
            None => 0,
            Some(level) => {
                let level = u8::try_from(level)
                    .map_err(|_| format!("compress: there is no level {level}"))?;
                crate::tcp_gateway::session::CompressionLevel::new(level)
                    .map_err(|err| format!("compress: {err}"))?;
                level as u32
            }
        };

        let connect_timeout_ms = match self.connect_timeout {
            None => 0,
            Some(0) => {
                return Err(
                    "connect_timeout is 0: leave it out for the default of 5 seconds".to_string(),
                )
            }
            Some(milliseconds) => milliseconds,
        };

        let mut sync_ssl_certificates = Vec::new();

        for cert_id in self.sync_ssl_certificates.unwrap_or_default() {
            let cert_id = cert_id.trim();

            if cert_id.is_empty() {
                return Err("sync_ssl_certificates has an empty id".to_string());
            }

            sync_ssl_certificates.push(cert_id.to_string());
        }

        Ok(StoredGatewayConnection {
            id,
            remote_host,
            private_key,
            compress,
            connect_timeout_ms,
            allow_incoming_forward_connections: self
                .allow_incoming_forward_connections
                .unwrap_or(false),
            sync_ssl_certificates,
            debug: self.debug.unwrap_or(false),
        })
    }
}

/// The id of a connection to a gateway: what the routes name, `gateway:<id>->...` - so up to 64
/// letters, digits, `-`, `_` and `.`. Whitespace around it is not part of it.
pub fn check_gateway_connection_id(id: &str) -> Result<&str, String> {
    let id = id.trim();

    if id.is_empty() {
        return Err("id is empty".to_string());
    }

    if id.len() > 64 {
        return Err("id is longer than 64 characters".to_string());
    }

    let fits = |c: char| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.');

    if !id.chars().all(fits) {
        return Err(
            "id may only have letters, digits, '-', '_' and '.' in it: a route names it as gateway:<id>->..."
                .to_string(),
        );
    }

    Ok(id)
}

/// `host:port` of a gateway server - a name, an IPv4 address or an IPv6 one in brackets.
fn check_remote_host(remote_host: &str) -> Result<&str, String> {
    let remote_host = remote_host.trim();

    let refused = || format!("remote_host '{remote_host}' is not host:port");

    if remote_host.is_empty() || remote_host.chars().any(char::is_whitespace) {
        return Err(refused());
    }

    let (host, port) = remote_host.rsplit_once(':').ok_or_else(refused)?;

    if host.is_empty() || !matches!(port.parse::<u16>(), Ok(port) if port > 0) {
        return Err(refused());
    }

    Ok(remote_host)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input() -> GatewayConnectionInput {
        GatewayConnectionInput {
            id: " london ".to_string(),
            remote_host: "gateway.example.com:9000".to_string(),
            private_key: "to-london".to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn what_a_call_leaves_out_takes_the_defaults_of_the_settings() {
        let stored = input().check().unwrap();

        assert_eq!(stored.id, "london");
        assert_eq!(stored.remote_host, "gateway.example.com:9000");
        assert_eq!(stored.private_key, "to-london");
        assert_eq!(stored.compress, 0);
        assert_eq!(stored.connect_timeout_ms, 0);
        assert!(!stored.allow_incoming_forward_connections);
        assert!(stored.sync_ssl_certificates.is_empty());
        assert!(!stored.debug);
    }

    #[test]
    fn what_a_call_gives_is_kept() {
        let stored = GatewayConnectionInput {
            compress: Some(1),
            connect_timeout: Some(2500),
            allow_incoming_forward_connections: Some(true),
            sync_ssl_certificates: Some(vec![" cert ".to_string()]),
            debug: Some(true),
            ..input()
        }
        .check()
        .unwrap();

        assert_eq!(stored.compress, 1);
        assert_eq!(stored.connect_timeout_ms, 2500);
        assert!(stored.allow_incoming_forward_connections);
        assert_eq!(stored.sync_ssl_certificates, ["cert"]);
        assert!(stored.debug);
    }

    #[test]
    fn an_id_a_route_can_not_name_is_refused() {
        for id in ["", "  ", "lon don", "a->b", "gateway:x", &"a".repeat(65)] {
            let err = GatewayConnectionInput {
                id: id.to_string(),
                ..input()
            }
            .check()
            .unwrap_err();
            assert!(err.starts_with("id "), "{id}: {err}");
        }

        assert!(check_gateway_connection_id("de-01_main.v2").is_ok());
    }

    #[test]
    fn a_remote_host_has_a_port() {
        for remote_host in ["10.0.0.1:9000", "[::1]:9000", "gateway.example.com:1"] {
            assert!(check_remote_host(remote_host).is_ok(), "{remote_host}");
        }

        for remote_host in [
            "",
            "10.0.0.1",
            "10.0.0.1:",
            ":9000",
            "10.0.0.1:0",
            "10.0.0.1:70000",
            "gateway example:9000",
        ] {
            assert!(check_remote_host(remote_host).is_err(), "{remote_host}");
        }
    }

    #[test]
    fn a_level_or_a_timeout_which_can_not_work_is_refused() {
        for compress in [256, 1000] {
            let err = GatewayConnectionInput {
                compress: Some(compress),
                ..input()
            }
            .check()
            .unwrap_err();
            assert!(err.starts_with("compress"), "{err}");
        }

        let unknown_level = crate::tcp_gateway::session::CompressionLevel::MAX as u64 + 1;
        assert!(GatewayConnectionInput {
            compress: Some(unknown_level),
            ..input()
        }
        .check()
        .is_err());

        assert!(GatewayConnectionInput {
            connect_timeout: Some(0),
            ..input()
        }
        .check()
        .is_err());

        assert!(GatewayConnectionInput {
            private_key: " ".to_string(),
            ..input()
        }
        .check()
        .is_err());

        assert!(GatewayConnectionInput {
            sync_ssl_certificates: Some(vec![" ".to_string()]),
            ..input()
        }
        .check()
        .is_err());
    }
}
