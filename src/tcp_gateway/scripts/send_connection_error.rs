use crate::tcp_gateway::*;

/// Refuses forward connection `connection_id` with `CONNECTION_ERROR` - a connect which failed or
/// is not allowed - and resets the connection if one was registered under the id. `send_force`
/// sends the error even when no connection was registered. The peer reads `err` as the reason of
/// a reset, whatever it says.
pub fn send_connection_error(
    gateway_connection: &TcpGatewayConnection,
    connection_id: u32,
    err: &str,
    send_force: bool,
    is_error: bool,
) {
    if is_error {
        let gateway_id = gateway_connection.get_gateway_id();
        println!("Gateway:[{}] {}", gateway_id.as_str(), err);
    }

    let connection_fail = TcpGatewayContract::ConnectionError {
        connection_id,
        error: err,
    };

    let removed = gateway_connection.remove_forward_connection_and_send(
        connection_id,
        &connection_fail,
        send_force,
    );

    if let Some(removed) = removed {
        removed.reset();
    }
}

/// Ends forward connection `connection_id` - if it is still registered - and tells the peer how
/// it ended, with `FIN` or `RST`. After a clean close the target gets what the peer sent and then
/// the end of the stream; after a reset its connection is reset at once.
pub fn end_forward_connection(
    gateway_connection: &TcpGatewayConnection,
    connection_id: u32,
    end: ConnectionEnd,
) {
    if let ConnectionEnd::Reset(reason) = end {
        println!(
            "Gateway:[{}] {}",
            gateway_connection.get_gateway_id(),
            reason
        );
    }

    let contract = end.to_contract(connection_id);

    let removed =
        gateway_connection.remove_forward_connection_and_send(connection_id, &contract, false);

    if let Some(removed) = removed {
        match end {
            ConnectionEnd::Closed => removed.disconnect(),
            ConnectionEnd::Reset(_) => removed.reset(),
        }
    }
}
