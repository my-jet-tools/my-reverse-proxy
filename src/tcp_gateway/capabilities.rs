//! Protocol extensions a peer advertises in its PINGs - see "Capabilities" in
//! docs/gateway-protocol.md. A frame type an extension adds goes only to a peer which advertised
//! the extension: one which predates it takes the type for an unknown one and closes the gateway
//! connection.

/// Per-connection flow control: `CONNECT_FC` and `WINDOW_UPDATE`.
pub const CAP_FLOW_CONTROL: u8 = 0x01;

/// Explicit ends of a tunnelled connection: `FIN` for a clean close, `RST` for a broken one.
pub const CAP_FIN_RST: u8 = 0x02;

/// What a current peer advertises.
pub const OWN_CAPABILITIES: u8 = CAP_FLOW_CONTROL | CAP_FIN_RST;

/// What a `PING` carries: this side's capabilities - the bare frame, as from a peer which predates
/// them, when there are none.
pub fn advertised(own_capabilities: u8) -> Option<u8> {
    (own_capabilities != 0).then_some(own_capabilities)
}
