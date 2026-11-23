//! The secure settings over the encrypted API: a YAML document of the schema of the settings file -
//! hosts with their endpoints and locations, variables, lists - kept in the secure store and
//! merged with the settings files like the dynamic settings file. Every call is encrypted with a
//! network key, and answered encrypted with the same key. See docs/secure-parameters.md.

use my_http_server::macros::MyHttpInput;

use super::{key_of_encrypted_request, store_refusal};

mod get_secure_settings_action;
pub use get_secure_settings_action::*;
mod set_secure_settings_action;
pub use set_secure_settings_action::*;

/// The secure settings document of a call: my-http-server has decrypted it before the action runs.
#[derive(MyHttpInput)]
pub struct EncryptedYamlHttpInput {
    #[http_body_raw(
        description = "The settings YAML, encrypted with a network key (Content-Encoding: aes128gcm): FlUrl's encrypted(&key), or bin/encrypted_call"
    )]
    pub body: Vec<u8>,
}
