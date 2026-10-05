use tokio_util::sync::CancellationToken;

use std::sync::Arc;

use crate::{
    app::SshSessionHandler,
    network_stream::*,
    tcp_utils::{ConnectionPumps, LoopBuffer},
};

pub enum WsDirection {
    ClientToServer,
    ServerToClient,
}

pub struct WsTrafficRecorder {
    pub domain: String,
    pub direction: WsDirection,
}

impl WsTrafficRecorder {
    pub fn record(&self, bytes: u64) {
        match self.direction {
            WsDirection::ClientToServer => crate::app::APP_CTX
                .traffic
                .record_ws_c2s(&self.domain, bytes),
            WsDirection::ServerToClient => crate::app::APP_CTX
                .traffic
                .record_ws_s2c(&self.domain, bytes),
        }
    }
}

/// How a pump ended - which decides what its writer's connection gets.
enum PumpEnd {
    /// The reader's end of stream, or the whole connection idle for the read timeout: the end of
    /// the stream - the writer is shut down.
    Closed,
    /// The writer's connection closed - its other end is gone, or the other pump closed it: the
    /// reader is lingered on while the other pump delivers what that end sent before.
    WriterClosed,
    /// A read or a write failed, or a write timed out: a reset - the writer is aborted, and so is
    /// the other pump's.
    Failed,
    /// The other pump failed: the writer is aborted.
    OtherFailed,
}

/// Copies `reader` into `writer`: one direction of a proxied connection, the other direction's
/// pump sharing `pumps`. A failure on either side resets both ends - each gets an error, not the
/// end of a stream cut short - where a writer can tell the two apart; see [`PumpEnd`].
pub async fn copy_streams<
    Reader: NetworkStreamReadPart + Send + 'static,
    Writer: NetworkStreamWritePart + Send + 'static,
>(
    mut reader: Reader,
    mut writer: Writer,
    mut loop_buffer: LoopBuffer,
    _ssh_session_handler: Option<SshSessionHandler>,
    recorder: Option<WsTrafficRecorder>,
    log_scope: Option<crate::app::ProxyLogScope>,
    // Shared by both pumps of one connection: the read timeout ends a pump only when neither
    // direction moved bytes for that long.
    pumps: Arc<ConnectionPumps>,
) {
    let direction_label = recorder
        .as_ref()
        .map(|r| match r.direction {
            WsDirection::ClientToServer => "c2s",
            WsDirection::ServerToClient => "s2c",
        })
        .unwrap_or("?");
    // For the websocket pump `log_scope` carries the endpoint + location + IP,
    // so route pump errors into that location's in-memory log instead of the
    // console. Raw TCP port-forward copies have no scope and stay on stderr.
    let log = |message: String| match &log_scope {
        Some(scope) => scope.write_always(message),
        None => eprintln!("{}", message),
    };

    // A writer which can tell that its connection is gone (a gateway tunnel connection, closed by
    // the peer, by the gateway going down or by the other pump dropping its half) stops this pump
    // at once. Without it a pump waiting on an idle reader would notice only on its next write,
    // or after read_timeout. The reader's own close is not watched here: data it still holds must
    // be read out first, and its read ends with EOF anyway.
    let writer_closed = writer.connection_closed();

    // Tells the other pump of the connection when this one is done, however it ends.
    let _running = pumps.running();

    let end = 'pump: loop {
        {
            let buf = loop_buffer.get_data();

            if !buf.is_empty() {
                let len = buf.len();
                let write_result = tokio::select! {
                    write_result = writer.write_all_with_timeout(buf, pumps.write_timeout()) => write_result,
                    _ = pumps.failed() => break 'pump PumpEnd::OtherFailed,
                };

                if let Err(err) = write_result {
                    log(format!(
                        "ws-pump {dir} write {n} bytes failed: {err:?}",
                        dir = direction_label,
                        n = len,
                        err = err,
                    ));

                    if writer_closed
                        .as_ref()
                        .is_some_and(|closed| closed.is_cancelled())
                    {
                        break 'pump PumpEnd::WriterClosed;
                    }
                    break 'pump PumpEnd::Failed;
                }

                // A write which took its time still moved bytes.
                pumps.bytes_moved();

                if let Some(rec) = recorder.as_ref() {
                    rec.record(len as u64);
                }

                loop_buffer.commit_read(len);
            }
        }

        let read_result = loop {
            // Idle is a property of the connection, not of this direction: while the other pump
            // moves bytes, a silent reader here is a one-way stream, not a dead peer.
            let Some(time_left) = pumps.read_time_left() else {
                break 'pump PumpEnd::Closed;
            };

            let read_result = tokio::select! {
                read_result = reader.read_with_timeout(loop_buffer.get_mut().unwrap(), time_left) => read_result,
                _ = wait_closed(writer_closed.as_ref()) => break 'pump PumpEnd::WriterClosed,
                _ = pumps.failed() => break 'pump PumpEnd::OtherFailed,
            };

            match read_result {
                Err(NetworkError::Timeout(_)) => continue,
                read_result => break read_result,
            }
        };

        match read_result {
            // The reader's end of stream - `read_with_timeout` reports it as `Disconnected`. A TLS
            // client which closes without a close_notify - many do - reads as `UnexpectedEof`:
            // its end of the stream too, not a failure.
            Ok(0) | Err(NetworkError::Disconnected) => break PumpEnd::Closed,
            Err(NetworkError::IoError(err)) if err.kind() == std::io::ErrorKind::UnexpectedEof => {
                break PumpEnd::Closed
            }
            Ok(read_size) => {
                pumps.bytes_moved();
                loop_buffer.advance(read_size);
            }
            Err(err) => {
                log(format!(
                    "ws-pump {dir} read failed: {err:?}",
                    dir = direction_label,
                    err = err,
                ));
                break PumpEnd::Failed;
            }
        }
    };

    // Within the write timeout: a peer which does not read may never let a shutdown through - a
    // TLS one has to take a close_notify first.
    let write_timeout = pumps.write_timeout();

    match end {
        PumpEnd::Closed => {
            if tokio::time::timeout(write_timeout, writer.shutdown_socket())
                .await
                .is_err()
            {
                log(format!(
                    "ws-pump {dir} shutdown timed out after {write_timeout:?}",
                    dir = direction_label,
                ));
                pumps.fail();
            }
        }
        PumpEnd::WriterClosed => linger(&mut reader, &pumps).await,
        PumpEnd::Failed => {
            // First: the other pump stops at once, whatever it waits for.
            pumps.fail();
            let _ = tokio::time::timeout(write_timeout, writer.abort_socket()).await;
        }
        PumpEnd::OtherFailed => {
            let _ = tokio::time::timeout(write_timeout, writer.abort_socket()).await;
        }
    }

    // A failed connection is reset at both ends, the reader's too: the other pump resets it as
    // its writer, but dropping a tunnel connection's half first would close it cleanly.
    if pumps.is_failed() {
        reader.abort_connection();
    }
}

/// Reads the reader - and drops what it sends - until it closes its side. Closing a socket with
/// unread data in it resets the connection, and a reset can make the client discard the response
/// tail the other pump writes to it. So the client is read for as long as the other pump runs,
/// however long the tail takes at the client's speed, and after that for up to the write timeout:
/// the client still has to read what is on its way and close. Not after the other pump failed:
/// then the client is reset anyway.
async fn linger(reader: &mut impl NetworkStreamReadPart, pumps: &ConnectionPumps) {
    let mut scratch = vec![0u8; 16 * 1024];

    let drain = async {
        while let Ok(read_size) = reader.read_from_socket(&mut scratch).await {
            if read_size == 0 {
                break;
            }
        }
    };

    let tail_delivered = async {
        pumps.other_pump_finished().await;
        tokio::time::sleep(pumps.write_timeout()).await;
    };

    tokio::select! {
        _ = drain => {}
        _ = tail_delivered => {}
        _ = pumps.failed() => {}
    }
}

async fn wait_closed(token: Option<&CancellationToken>) {
    match token {
        Some(token) => token.cancelled().await,
        None => std::future::pending().await,
    }
}
