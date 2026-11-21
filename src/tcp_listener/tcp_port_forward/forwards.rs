use crate::{
    app::SshSessionHandler, network_stream::*, tcp_utils::LoopBuffer,
    types::AcceptedServerConnection, types::HttpTimeouts,
};

pub async fn handle_port_forward<TRemoteNetworkStream: NetworkStream + Send + Sync + 'static>(
    server_stream: AcceptedServerConnection,
    remote_stream: TRemoteNetworkStream,
    ssh_session_handler: Option<SshSessionHandler>,
    timeouts: HttpTimeouts,
    slot: crate::app::ConnectionSlot,
) {
    // The connection is held while either of its pumps runs.
    let slot = std::sync::Arc::new(slot);
    let (remote_reader, remote_writer) = remote_stream.split();
    let pumps = std::sync::Arc::new(crate::tcp_utils::ConnectionPumps::new(timeouts));

    // Owned halves: a failed connection resets the client's socket - the client gets an error,
    // not the end of a stream cut short.
    let (server_reader, server_writer, (server_to_remote, remote_to_server)) = match server_stream {
        AcceptedServerConnection::Tcp { network_stream, .. } => {
            // A pump writes what comes as it comes: a piece which follows another must not wait
            // for the client to acknowledge the first.
            let _ = network_stream.set_nodelay(true);
            let (read, write) = network_stream.into_split();
            (
                MyOwnedReadHalf::from(read),
                MyOwnedWriteHalf::from(write),
                (
                    "tcp_forward_copy_server_to_remote_tcp",
                    "tcp_forward_copy_remote_to_server_tcp",
                ),
            )
        }
        #[cfg(unix)]
        AcceptedServerConnection::Unix(unix_stream) => {
            let (read, write) = unix_stream.into_split();
            (
                MyOwnedReadHalf::from(read),
                MyOwnedWriteHalf::from(write),
                (
                    "tcp_forward_copy_server_to_remote_unix",
                    "tcp_forward_copy_remote_to_server_unix",
                ),
            )
        }
    };

    let server_to_remote_slot = slot.clone();
    let server_to_remote_pumps = pumps.clone();
    crate::app::spawn_named(server_to_remote, async move {
        let _slot = server_to_remote_slot;
        crate::tcp_utils::copy_streams(
            server_reader,
            remote_writer,
            LoopBuffer::new(),
            ssh_session_handler,
            None,
            None,
            server_to_remote_pumps,
        )
        .await
    });
    crate::app::spawn_named(remote_to_server, async move {
        let _slot = slot;
        crate::tcp_utils::copy_streams(
            remote_reader,
            server_writer,
            LoopBuffer::new(),
            None,
            None,
            None,
            pumps,
        )
        .await
    });
}
