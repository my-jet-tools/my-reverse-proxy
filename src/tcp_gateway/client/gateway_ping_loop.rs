use std::{sync::Arc, time::Duration};

use rust_extensions::date_time::DateTimeAsMicroseconds;
use tokio_util::sync::CancellationToken;

use crate::tcp_gateway::{advertised, TcpGatewayConnection, TcpGatewayContract};

const PING_DELAY: Duration = Duration::from_secs(3);

/// Pings the server until the connection dies. Returns at once when the connection is closed
/// some other way (the server closed it, the writer failed), so the client reconnects without
/// waiting for the next ping.
///
/// Every PING carries this side's capabilities. With capabilities the first one goes out at once:
/// the server learns them a round trip after the connection came up, and its connects wait for
/// them meanwhile. Without, the first one goes out after [`PING_DELAY`], as from a client which
/// predates capabilities.
pub async fn gateway_ping_loop(gateway_connection: Arc<TcpGatewayConnection>, debug: bool) {
    let disconnected = gateway_connection.disconnected_token();
    let capabilities = advertised(gateway_connection.own_capabilities());

    if capabilities.is_none() && !sleep_or_disconnected(&disconnected).await {
        return;
    }

    loop {
        let now = DateTimeAsMicroseconds::now();

        let incoming_interval = now - gateway_connection.get_last_incoming_payload_time();

        let incoming_interval_sec = incoming_interval.get_full_seconds();

        if incoming_interval_sec > 9 {
            if debug {
                println!(
                    "Detected dead Tcp Gateway connection to {} with id [{}]",
                    gateway_connection.addr.as_str(),
                    gateway_connection.get_gateway_id()
                );
            }

            gateway_connection.disconnect_gateway();
            break;
        }

        gateway_connection.ping_stop_watch.reset_and_start();
        let sent_ok = gateway_connection.send_payload(&TcpGatewayContract::Ping { capabilities });

        if !sent_ok {
            break;
        }

        if !sleep_or_disconnected(&disconnected).await {
            break;
        }
    }
}

/// Sleeps [`PING_DELAY`]; `false` when the connection is closed meanwhile.
async fn sleep_or_disconnected(disconnected: &CancellationToken) -> bool {
    tokio::select! {
        _ = disconnected.cancelled() => false,
        _ = tokio::time::sleep(PING_DELAY) => true,
    }
}
