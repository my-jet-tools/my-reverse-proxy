//! The public keys the gateway server of this proxy lets in, kept in the secure store, over the
//! encrypted API: every call is encrypted with a network key, and answered encrypted with the
//! same key. They count besides the files of `gateway_server.authorized_keys`, from the next
//! handshake on. See docs/secure-parameters.md.

use super::{key_of_encrypted_request, parse_call, store_refusal, EncryptedJsonHttpInput};

mod set_gateway_authorized_key_action;
pub use set_gateway_authorized_key_action::*;
mod delete_gateway_authorized_key_action;
pub use delete_gateway_authorized_key_action::*;
mod list_gateway_authorized_keys_action;
pub use list_gateway_authorized_keys_action::*;
