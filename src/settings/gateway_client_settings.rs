use std::time::Duration;

use ed25519_dalek::SigningKey;
use serde::*;
use ssh_key::{private::Ed25519Keypair, PrivateKey};

use crate::tcp_gateway::session::CompressionLevel;

use super::SshConfigSettings;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct GatewayClientSettings {
    pub remote_host: String,
    pub ssh_credentials: String,
    /// The compression level of the gateway connection: 0 or nothing - off, from 1 on - a row
    /// of the table in docs/gateway-compression.md.
    pub compress: Option<u8>,

    pub debug: Option<bool>,
    pub allow_incoming_forward_connections: Option<bool>,
    /// Connect timeout for the gateway-client link, in milliseconds.
    pub connect_timeout: Option<u64>,
    pub sync_ssl_certificates: Option<Vec<String>>,
}

impl GatewayClientSettings {
    pub fn is_debug(&self) -> bool {
        self.debug.unwrap_or(false)
    }

    pub fn get_compression(&self, client_id: &str) -> Result<CompressionLevel, String> {
        CompressionLevel::new(self.compress.unwrap_or(0))
            .map_err(|err| format!("Gateway client '{client_id}': compress: {err}"))
    }

    pub fn get_allow_incoming_forward_connections(&self) -> bool {
        self.allow_incoming_forward_connections.unwrap_or(false)
    }

    pub fn get_connect_timeout(&self) -> Duration {
        match self.connect_timeout {
            Some(value) => Duration::from_millis(value),
            None => Duration::from_secs(5),
        }
    }

    pub fn get_sync_ssl_certificates(&self) -> Vec<String> {
        self.sync_ssl_certificates.clone().unwrap_or_default()
    }

    pub fn load_signing_key(
        &self,
        client_id: &str,
        ssh_registry: &std::collections::HashMap<String, SshConfigSettings>,
    ) -> Result<SigningKey, String> {
        let ssh_entry = ssh_registry
            .get(self.ssh_credentials.as_str())
            .ok_or_else(|| {
                format!(
                "Gateway client '{client_id}': ssh_credentials '{}' not found in 'ssh:' registry",
                self.ssh_credentials
            )
            })?;

        let key_path = ssh_entry.private_key_file.as_deref().ok_or_else(|| {
            format!(
                "Gateway client '{client_id}': ssh entry '{}' has no private_key_file — gateway requires a private key, password-only entries are not supported",
                self.ssh_credentials
            )
        })?;

        let resolved = rust_extensions::file_utils::format_path(key_path).to_string();

        let raw = std::fs::read(resolved.as_str()).map_err(|err| {
            format!(
                "Gateway client '{client_id}': cannot read private_key_file '{resolved}': {err}"
            )
        })?;

        // The OpenSSH PEM parser is strict about boundaries: a stray trailing
        // newline (e.g. an extra blank line left by an editor) makes it fail
        // with `PreEncapsulationBoundary`. Trim trailing whitespace so a benign
        // edit to the key file doesn't break the gateway link.
        let private = PrivateKey::from_openssh(raw.trim_ascii_end()).map_err(|err| {
            format!(
                "Gateway client '{client_id}': cannot parse OpenSSH private key '{resolved}': {err}"
            )
        })?;

        let unlocked = if private.is_encrypted() {
            let phrase = ssh_entry.passphrase.as_deref().ok_or_else(|| {
                format!(
                    "Gateway client '{client_id}': private key '{resolved}' is encrypted but ssh entry has no passphrase"
                )
            })?;
            private.decrypt(phrase.as_bytes()).map_err(|err| {
                format!(
                    "Gateway client '{client_id}': failed to decrypt private key '{resolved}' with passphrase: {err}"
                )
            })?
        } else {
            private
        };

        let keypair: &Ed25519Keypair = unlocked.key_data().ed25519().ok_or_else(|| {
            format!("Gateway client '{client_id}': private key '{resolved}' is not Ed25519")
        })?;

        Ok(SigningKey::from_bytes(&keypair.private.to_bytes()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The settings of a client as they are in the file, with `compress` the way it is given.
    fn client(compress: &str) -> Result<GatewayClientSettings, serde_yaml::Error> {
        serde_yaml::from_str(&format!(
            "remote_host: 10.0.0.1:30000\nssh_credentials: gateway\n{compress}"
        ))
    }

    #[test]
    fn compress_is_the_compression_level() {
        let level_of = |compress: &str| client(compress).unwrap().get_compression("london");

        assert_eq!(level_of(""), Ok(CompressionLevel::OFF));
        assert_eq!(level_of("compress: 0"), Ok(CompressionLevel::OFF));

        for level in 1..=CompressionLevel::MAX {
            let compression = level_of(&format!("compress: {level}")).unwrap();
            assert_eq!(compression.as_u8(), level);
            assert!(compression.is_on());
        }

        // A level the table has no row for: said with the name of the client it is set for.
        let err = level_of(&format!("compress: {}", CompressionLevel::MAX + 1)).unwrap_err();
        assert!(err.contains("Gateway client 'london': compress:"), "{err}");
        assert!(err.contains("is not known"), "{err}");
    }

    /// It was a yes or a no before the levels: neither is a level, and the settings which
    /// still say so are not read as some level nobody chose.
    #[test]
    fn compress_which_is_not_a_level_is_not_read() {
        for compress in [
            "compress: true",
            "compress: false",
            "compress: -1",
            "compress: 300",
        ] {
            assert!(client(compress).is_err(), "{compress}");
        }
    }
}
