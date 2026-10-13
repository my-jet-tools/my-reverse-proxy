use std::{sync::Arc, time::Duration};

use rust_extensions::remote_endpoint::RemoteEndpointOwned;

use crate::{configurations::TcpEndpointHostConfig, types::AcceptedServerConnection};

pub async fn handle_connection(
    mut accepted_server_connection: AcceptedServerConnection,
    configuration: Arc<TcpEndpointHostConfig>,
    gateway_id: &Arc<String>,
    remote_endpoint: Arc<RemoteEndpointOwned>,
) {
    let connection_ip = accepted_server_connection.get_addr();
    if configuration.debug {
        println!(
            "Accepted connection forwarded to {}->{}",
            gateway_id.as_str(),
            remote_endpoint.as_str()
        );
    }

    let gateway_connection =
        crate::app::APP_CTX.get_gateway_by_id_with_next_connection_id(gateway_id);

    if gateway_connection.is_none() {
        if configuration.debug {
            println!(
                "Error connecting to remote tcp {} server. Gateway connection [{}] is not found. Closing incoming connection: {:?}",
                remote_endpoint.as_str(),
                gateway_id.as_str(),
                connection_ip
            );
        }
        let _ = accepted_server_connection.shutdown().await;
        return;
    }

    let (gateway_connection, connection_id) = gateway_connection.unwrap();

    let connection_result = gateway_connection
        .connect_to_forward_proxy_connection(
            remote_endpoint.clone(),
            Duration::from_secs(5),
            connection_id,
        )
        .await;

    if let Err(err) = &connection_result {
        if configuration.debug {
            println!(
                "Error connecting to remote tcp {} server: {:?}. Closing incoming connection: {:?}",
                remote_endpoint.as_str(),
                err,
                connection_ip
            );
        }
        let _ = accepted_server_connection.shutdown().await;
        return;
    }

    let proxy_connection = connection_result.unwrap();

    if configuration.debug {
        println!(
            "Accepted connection to {}->{}. Connection_id: {}",
            gateway_id,
            remote_endpoint.as_str(),
            connection_id,
        );
    }

    crate::app::spawn_named(
        "tcp_forward_gateway",
        super::handle_port_forward(
            accepted_server_connection,
            proxy_connection,
            None,
            configuration.timeouts,
        ),
    );
}
