use serde::*;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SshConfigSettings {
    pub password: Option<crate::types::ProtectedString>,
    pub private_key_file: Option<String>,
    pub passphrase: Option<crate::types::ProtectedString>,
}
