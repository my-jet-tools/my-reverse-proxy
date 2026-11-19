use ed25519_dalek::VerifyingKey;
use serde::*;
use ssh_key::PublicKey;

use crate::types::WhiteListedIpList;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct GatewayServerSettings {
    pub port: u16,
    /// Files of OpenSSH public keys: who the server lets in, besides the keys the secure store
    /// authorizes (`/api/gateway-authorized-keys/v1/...`). May be left out: then only those.
    #[serde(default)]
    pub authorized_keys: Vec<String>,
    pub allowed_ip: Option<Vec<String>>,
    pub debug: Option<bool>,
}

impl GatewayServerSettings {
    pub fn is_debug(&self) -> bool {
        self.debug.unwrap_or(false)
    }

    /// The keys of the files of `authorized_keys`. None is no error: the server lets in the keys
    /// the secure store authorizes then - nobody until it is initialized.
    pub fn load_authorized_keys(&self) -> Result<Vec<VerifyingKey>, String> {
        if self.authorized_keys.is_empty() {
            println!(
                "Gateway server: no authorized_keys files - it lets in only the keys the secure store authorizes"
            );
        }

        let mut keys = Vec::with_capacity(self.authorized_keys.len());
        for path in &self.authorized_keys {
            let resolved =
                super::expand_home(path).map_err(|err| format!("Gateway server: {err}"))?;
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

    /// `allowed_ip` as a whitelist, `None` when it is not set. Entries are IPv4 addresses,
    /// `from-to` ranges and subnets (`10.0.0.0/24`), the same as in `ip_white_lists`; an empty
    /// list restricts nothing.
    pub fn get_allowed_ip_list(&self) -> Result<Option<WhiteListedIpList>, String> {
        // Unlike a list of `ip_white_lists`, which lets nobody in when it is empty.
        let Some(items) = self.allowed_ip.as_ref().filter(|items| !items.is_empty()) else {
            return Ok(None);
        };

        // A wrong entry fails the startup with a message saying which one it is.
        for itm in items {
            crate::types::check_ip_white_list_entry(itm)
                .map_err(|err| format!("Gateway server: invalid allowed_ip entry: {err}"))?;
        }

        Ok(Some(WhiteListedIpList::new(items)))
    }
}
