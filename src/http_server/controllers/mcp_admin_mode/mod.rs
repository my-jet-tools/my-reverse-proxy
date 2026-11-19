//! The admin mode of MCP: opened, for some minutes, only by an encrypted call of the control port.

use super::{key_of_encrypted_request, parse_call, EncryptedJsonHttpInput};

mod set_mcp_admin_mode_action;
pub use set_mcp_admin_mode_action::*;
