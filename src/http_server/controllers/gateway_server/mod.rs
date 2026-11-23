//! The gateway server of the secure store over the encrypted API: every call is encrypted with a
//! network key, and answered encrypted with the same key. It is what `gateway_server` of the
//! settings says, with no `authorized_keys` files: it lets in the keys the store authorizes. It
//! is started as soon as it is set, and after every initialize from then on. See
//! docs/secure-parameters.md.

use super::{key_of_encrypted_request, parse_call, store_refusal, EncryptedJsonHttpInput};

mod set_gateway_server_action;
pub use set_gateway_server_action::*;
mod delete_gateway_server_action;
pub use delete_gateway_server_action::*;
mod get_gateway_server_action;
pub use get_gateway_server_action::*;
