use std::sync::Arc;

use rust_extensions::SliceOrVec;
use tokio::io::AsyncReadExt;

use crate::tcp_gateway::{
    GetFileStatus, TcpGatewayConnection, FILE_REQUEST_TIMEOUT, MAX_FILE_RESPONSE_SIZE,
};

/// Answers a file request. The file is read only once one of the connection's file response
/// slots is free, and the response is given up if it can not be queued in time - on a slow link
/// pending responses do not pile up in memory.
///
/// The requester waits FILE_REQUEST_TIMEOUT for the whole round trip, counted from before the
/// request crossed the link. This side has half of it for waiting and reading, so that a response
/// it does queue still has the other half to cross the link before the requester gives up.
pub async fn serve_file(
    request_id: u32,
    path: String,
    gateway_connection: Arc<TcpGatewayConnection>,
) {
    crate::app::spawn_named("tcp_gateway_serve_file", async move {
        let deadline = tokio::time::Instant::now() + FILE_REQUEST_TIMEOUT / 2;
        let disconnected = gateway_connection.disconnected_token();

        let slot = tokio::select! {
            _ = disconnected.cancelled() => return,
            slot = tokio::time::timeout_at(deadline, gateway_connection.file_response_slots.acquire()) => slot,
        };

        let Ok(Ok(_slot)) = slot else {
            report_dropped(&gateway_connection, path.as_str());
            return;
        };

        // A read which hangs - a stalled network file system - must not keep the slot either.
        let content = tokio::select! {
            _ = disconnected.cancelled() => return,
            content = tokio::time::timeout_at(deadline, read_file_to_serve(path.as_str())) => content,
        };

        let Ok(content) = content else {
            report_dropped(&gateway_connection, path.as_str());
            return;
        };

        let payload = match &content {
            Ok(content) => crate::tcp_gateway::TcpGatewayContract::GetFileResponse {
                request_id,
                status: GetFileStatus::Ok,
                content: SliceOrVec::AsSlice(content),
            },

            Err(_) => crate::tcp_gateway::TcpGatewayContract::GetFileResponse {
                request_id,
                status: GetFileStatus::Error,
                content: SliceOrVec::AsSlice(&[]),
            },
        };

        let queued = tokio::select! {
            _ = disconnected.cancelled() => return,
            queued = tokio::time::timeout_at(deadline, gateway_connection.send_payload_with_backpressure(&payload)) => queued,
        };

        if queued.is_err() {
            report_dropped(&gateway_connection, path.as_str());
        }
    });
}

fn report_dropped(gateway_connection: &TcpGatewayConnection, path: &str) {
    println!(
        "Gateway:[{}]. File response for {} is dropped: it could not be sent in time",
        gateway_connection.get_gateway_id(),
        crate::types::path_for_log(path),
    );
}

/// The response travels as a single frame, and the peer closes the whole gateway connection on
/// a frame above its limit - a file too big for one frame is answered with an error instead.
/// Only regular files are served, and the read itself is capped: the size a device or a procfs
/// file reports says nothing about how much it yields.
///
/// The requester sends a leading `~` as it is: it is the home directory of this side, and when
/// that is not known the file can not be read either.
async fn read_file_to_serve(path: &str) -> Result<Vec<u8>, ()> {
    let path = crate::settings::expand_home(path).map_err(|_| ())?;
    let path = path.as_str();

    let metadata = tokio::fs::metadata(path).await.map_err(|_| ())?;

    if !metadata.is_file() {
        return Err(());
    }

    if metadata.len() > MAX_FILE_RESPONSE_SIZE as u64 {
        println!(
            "Gateway: file {} is {} bytes - more than the {} bytes a gateway file response carries",
            crate::types::path_for_log(path),
            metadata.len(),
            MAX_FILE_RESPONSE_SIZE
        );
        return Err(());
    }

    let file = tokio::fs::File::open(path).await.map_err(|_| ())?;

    let mut content = Vec::with_capacity(metadata.len() as usize);
    file.take(MAX_FILE_RESPONSE_SIZE as u64 + 1)
        .read_to_end(&mut content)
        .await
        .map_err(|_| ())?;

    // The file may have grown since the metadata was read.
    if content.len() > MAX_FILE_RESPONSE_SIZE {
        return Err(());
    }

    Ok(content)
}
