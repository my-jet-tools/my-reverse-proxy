//! The connections to gateways of the secure store over the encrypted API: every call is
//! encrypted with a network key, and answered encrypted with the same key. A connection is what
//! an entry of `gateway_clients` of the settings says, with the handshake signed by a private key
//! of the store; its client is started as soon as it is set, and stopped when it is removed. See
//! docs/secure-parameters.md.

use super::{key_of_encrypted_request, parse_call, store_refusal, EncryptedJsonHttpInput};

mod set_gateway_connection_action;
pub use set_gateway_connection_action::*;
mod delete_gateway_connection_action;
pub use delete_gateway_connection_action::*;
mod list_gateway_connections_action;
pub use list_gateway_connections_action::*;
mod models;
pub use models::*;
