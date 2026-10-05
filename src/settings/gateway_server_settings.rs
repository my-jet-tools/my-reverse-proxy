use std::net::Ipv4Addr;

use ed25519_dalek::VerifyingKey;
use serde::*;
use ssh_key::PublicKey;

use crate::types::WhiteListedIpList;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct GatewayServerSettings {
    pub port: u16,
    pub authorized_keys: Vec<String>,
    pub allowed_ip: Option<Vec<String>>,
    pub debug: Option<bool>,
}

impl GatewayServerSettings {
    pub fn is_debug(&self) -> bool {
        self.debug.unwrap_or(false)
    }

    pub fn load_authorized_keys(&self) -> Result<Vec<VerifyingKey>, String> {
        if self.authorized_keys.is_empty() {
            return Err(
                "Gateway server: 'authorized_keys' must contain at least one path".to_string(),
            );
        }

        let mut keys = Vec::with_capacity(self.authorized_keys.len());
        for path in &self.authorized_keys {
            let resolved = rust_extensions::file_utils::format_path(path).to_string();
            let content = std::fs::read_to_string(resolved.as_str()).map_err(|err| {
                format!("Gateway server: cannot read pubkey file '{resolved}': {err}")
            })?;

            let pub_key = PublicKey::from_openssh(content.trim()).map_err(|err| {
                format!("Gateway server: cannot parse pubkey '{resolved}': {err}")
            })?;

            let ed25519 = pub_key
                .key_data()
                .ed25519()
                .ok_or_else(|| format!("Gateway server: pubkey '{resolved}' is not Ed25519"))?;

            let verifying = VerifyingKey::from_bytes(&ed25519.0).map_err(|err| {
                format!("Gateway server: invalid Ed25519 pubkey in '{resolved}': {err}")
            })?;

            keys.push(verifying);
        }

        Ok(keys)
    }

    /// `allowed_ip` as a whitelist, `None` when it is not set. Entries are IPv4 addresses or
    /// `from-to` ranges, the same as in `ip_white_lists`; an empty list restricts nothing.
    pub fn get_allowed_ip_list(&self) -> Result<Option<WhiteListedIpList>, String> {
        let Some(items) = self.allowed_ip.as_ref() else {
            return Ok(None);
        };

        // `WhiteListedIpList` panics on an entry it can not parse - fail with a message saying
        // which entry is wrong instead.
        for itm in items {
            let is_valid = match itm.split_once('-') {
                Some((from, to)) => {
                    from.parse::<Ipv4Addr>().is_ok() && to.parse::<Ipv4Addr>().is_ok()
                }
                None => itm.parse::<Ipv4Addr>().is_ok(),
            };

            if !is_valid {
                return Err(format!(
                    "Gateway server: invalid allowed_ip entry '{itm}' - an IPv4 address or an IPv4 from-to range is expected"
                ));
            }
        }

        Ok(Some(WhiteListedIpList::new(items)))
    }
}
