use std::{sync::Arc, time::Duration};

use crate::tcp_gateway::{forwarded_connection::TcpGatewayForwardConnection, *};

/// `peer_window`: the initiator's receive window, as its `CONNECT` says.
pub async fn handle_forward_connect(
    connection_id: u32,
    remote_host: String,
    timeout: Duration,
    peer_window: u32,
    gateway_connection: Arc<TcpGatewayConnection>,
) {
    if gateway_connection.has_forward_connection(connection_id) {
        let err =
        format!("Attempt to establish client forward connection is fail. ConnectionId {} is already has a connection", connection_id);

        crate::tcp_gateway::scripts::send_connection_error(
            gateway_connection.as_ref(),
            connection_id,
            err.as_str(),
            true,
            true,
        );
        return;
    }

    // Under the protocol floor a chunk might never fit, and our sender would stall without a word.
    if (peer_window as usize) < MIN_RECEIVE_WINDOW {
        crate::tcp_gateway::scripts::send_connection_error(
            gateway_connection.as_ref(),
            connection_id,
            "Flow control: window out of range",
            true,
            true,
        );
        return;
    }

    let connection_result = TcpGatewayForwardConnection::connect(
        connection_id,
        gateway_connection.as_ref(),
        Arc::new(remote_host),
        timeout,
        peer_window,
    )
    .await;

    let (forward_connection, read) = match connection_result {
        Ok(result) => result,
        Err(err) => {
            crate::tcp_gateway::scripts::send_connection_error(
                gateway_connection.as_ref(),
                connection_id,
                err.as_str(),
                true,
                true,
            );
            return;
        }
    };

    let forward_connection = Arc::new(forward_connection);

    // Registered before CONNECT_OK goes out and before the upstream is read: the peer starts
    // sending as soon as it sees CONNECT_OK, and the first upstream bytes go back under this
    // id - neither may meet an id this side does not know yet.
    if !gateway_connection.add_forward_connection(connection_id, forward_connection.clone()) {
        // The gateway connection went down while we were connecting.
        forward_connection.reset();
        return;
    }

    // The initiator's credit for what it sends - this side's window - right ahead of CONNECT_OK,
    // so the stream handed out on CONNECT_OK can write at once. In order, not expedited:
    // CONNECT_OK goes in order anyway, and must never overtake it.
    gateway_connection.send_payload(&TcpGatewayContract::WindowUpdate {
        connection_id,
        credit: FLOW_CONTROL_WINDOW as u32,
    });

    let connected_payload = TcpGatewayContract::Connected { connection_id };
    gateway_connection.send_payload(&connected_payload);

    forward_connection.start(read, gateway_connection.clone());
}
