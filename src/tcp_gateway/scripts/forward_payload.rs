use crate::tcp_gateway::{TcpGatewayConnection, TcpGatewayContract};

pub fn forward_payload(
    gateway_connection: &TcpGatewayConnection,
    connection_id: u32,
    payload: &[u8],
) {
    let Some(forward_connection) = gateway_connection.get_forward_connection(connection_id) else {
        // Closed on this side already - make sure the peer closes its end too instead of
        // writing into the void.
        gateway_connection.send_payload(&TcpGatewayContract::ConnectionError {
            connection_id,
            error: "Connection is not found",
        });
        return;
    };

    // Counted even when the writer has failed and drops it: the initiator spent credit on it, and
    // a connection whose writer failed is ending - that credit does not come back.
    if !forward_connection.count_received(payload.len()) {
        gateway_connection
            .close_on_flow_control_violation(connection_id, "Flow control: window exceeded");
        return;
    }

    // A failed write lowers the connection's flag. Its read loop then forwards what the upstream
    // still sends and closes the connection itself - after its last data frame, which a close
    // sent from here, a control frame skipping the write budget, could overtake.
    forward_connection.send_payload(payload);
}
