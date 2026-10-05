use std::{sync::Arc, time::Duration};

use tokio::sync::Semaphore;

use crate::{network_stream::*, tcp_gateway::*};

pub struct TcpGatewayForwardConnection {
    inner: Arc<TcpConnectionInner>,
    connection_id: u32,
    remote_endpoint: Arc<String>,
    /// The initiator's credit for what the target sends back; `None` without flow control.
    /// Closed when the connection is unregistered.
    send_window: Option<Semaphore>,
    /// This side's window for what the initiator sends to the target; `None` without flow
    /// control.
    receive_window: Option<Arc<ReceiveWindow>>,
}

impl TcpGatewayForwardConnection {
    /// Connects to `remote_endpoint`. The read half comes back separately and goes to
    /// [`Self::start`] once the connection is registered: reading the upstream earlier could
    /// send its first bytes under a connection id the gateway connection does not know yet.
    ///
    /// `peer_window`: the initiator's receive window from `CONNECT_FC` - `Some` makes the
    /// connection flow controlled.
    pub async fn connect(
        connection_id: u32,
        gateway_connection: &TcpGatewayConnection,
        remote_endpoint: Arc<String>,
        timeout: Duration,
        peer_window: Option<u32>,
    ) -> Result<(Self, MyOwnedReadHalf), String> {
        println!(
            "Gateway:[{}]. Establishing Forwarded connection to endpoint {} with id {}",
            gateway_connection.get_gateway_id(),
            remote_endpoint.as_str(),
            connection_id
        );

        let remote_endpoint_str = remote_endpoint.as_str();
        let tcp_stream = if remote_endpoint.starts_with('/') {
            connect_to_unix_socket(remote_endpoint_str, connection_id, timeout).await?
        } else {
            connect_to_tcp_socket(remote_endpoint_str, connection_id, timeout).await?
        };

        println!(
            "Gateway:[{}]. Established Forwarded connection to endpoint {} with id {}",
            gateway_connection.get_gateway_id(),
            remote_endpoint.as_str(),
            connection_id
        );

        let (read, write) = tcp_stream.into_split();

        let receive_window =
            peer_window.map(|_| gateway_connection.new_receive_window(connection_id));
        let inner = TcpConnectionInner::new_raw_passthrough(write, receive_window.clone());
        let send_window =
            peer_window.map(|window| Semaphore::new((window as usize).min(MAX_SEND_CREDIT)));

        let result = Self {
            connection_id,
            inner,
            remote_endpoint,
            send_window,
            receive_window,
        };

        Ok((result, read))
    }

    pub fn send_window(&self) -> Option<&Semaphore> {
        self.send_window.as_ref()
    }

    /// A payload of `len` bytes for the target arrived. `false`: the initiator sent past this
    /// side's window.
    pub fn count_received(&self, len: usize) -> bool {
        self.receive_window
            .as_ref()
            .is_none_or(|receive_window| receive_window.received(len))
    }

    pub fn add_send_credit(&self, credit: u32) {
        if let Some(send_window) = self.send_window.as_ref() {
            add_credit(send_window, credit);
        }
    }

    /// What is held for the target, not yet written; `None` without flow control.
    #[cfg(test)]
    pub fn buffered_for_tests(&self) -> Option<usize> {
        self.receive_window
            .as_ref()
            .map(|receive_window| receive_window.held())
    }

    /// The state after a failed write to the target: the flag down, the writer stopped, the
    /// connection still registered.
    #[cfg(test)]
    pub fn fail_writer_for_tests(&self) {
        self.inner.fail_writes_for_tests();
    }

    pub fn get_remote_endpoint(&self) -> Arc<String> {
        self.remote_endpoint.clone()
    }

    pub fn send_payload(&self, payload: &[u8]) -> bool {
        if self.inner.send_payload(payload.to_vec()) {
            return true;
        }

        // Once: after a failed write, or once the upstream closed, every frame still on its way
        // ends up here.
        if self.inner.disconnect() {
            println!(
                "Connection: {}. Send to Forward Connection {}",
                self.connection_id,
                payload.len()
            );
        }
        false
    }

    /// Closes the connection. What the peer has sent so far still reaches the downstream
    /// service; the upstream read loop stops - also one waiting for credit: there is nobody to
    /// send to any more. Called only when the connection is unregistered; a failed write lowers
    /// the flag alone, so the forwarding after it still gets credit.
    pub fn disconnect(&self) {
        self.inner.disconnect();

        if let Some(send_window) = self.send_window.as_ref() {
            send_window.close();
        }
    }

    /// Resets the connection: what is queued for the downstream service is dropped and its
    /// connection is reset - the service gets an error, not the end of the stream - and the
    /// upstream read loop stops at once. Called only when the connection is unregistered: the
    /// peer reset it, or the gateway connection is gone.
    pub fn reset(&self) {
        self.inner.reset();

        if let Some(send_window) = self.send_window.as_ref() {
            send_window.close();
        }
    }

    pub fn start(&self, read: MyOwnedReadHalf, gateway_connection: Arc<TcpGatewayConnection>) {
        crate::app::spawn_named(
            "tcp_gateway_forwarded_read_loop",
            read_loop(
                read,
                gateway_connection,
                self.inner.clone(),
                self.connection_id,
                self.remote_endpoint.clone(),
            ),
        );
    }
}

async fn read_loop(
    mut read: MyOwnedReadHalf,
    gateway_connection: Arc<TcpGatewayConnection>,
    write: Arc<TcpConnectionInner>,
    connection_id: u32,
    remote_host: Arc<String>,
) {
    // The connection's flag: cancelled when the connection is closed - by the peer, together
    // with the gateway connection, or because the write to the upstream failed.
    let disconnected = write.disconnected_token();

    // Cancelled when the connection is reset: the loop stops at once, whatever it waits for.
    let reset = write.reset_token();

    // One buffer per forwarded connection: it is read into through its spare capacity, so it
    // is never zeroed up front and only the pages a read really fills become resident. Its
    // capacity caps a read at the payload size of one frame.
    let mut buf = Vec::with_capacity(MAX_PAYLOAD_CHUNK);

    // Set when the flag went down because the write to the upstream failed, while the peer and
    // the gateway connection are fine. The upstream may have answered before it stopped reading -
    // a 413 for an upload it refuses - so what it sends is still read and forwarded until it
    // closes, and this loop closes the connection after the last data frame.
    let mut write_failed_at: Option<tokio::time::Instant> = None;

    let peer_gone = loop {
        buf.clear();

        // After a failed write the upstream is forwarded for WRITE_FAILED_DRAIN_LIMIT at most. The
        // deadline is checked here and not only around the read: an upstream which keeps its socket
        // full has every read ready at once, and a timeout looks at its deadline only when the
        // future it wraps is pending.
        let drain_deadline = write_failed_at.map(|at| at + WRITE_FAILED_DRAIN_LIMIT);
        if drain_deadline.is_some_and(|deadline| tokio::time::Instant::now() >= deadline) {
            close_after_write_failure(&gateway_connection, connection_id, &remote_host);
            break false;
        }

        let read_result = match drain_deadline {
            Some(deadline) => tokio::select! {
                biased;
                read_result = tokio::time::timeout_at(deadline, read.read_buf(&mut buf)) => {
                    match read_result {
                        Ok(read_result) => read_result,
                        Err(_) => {
                            close_after_write_failure(&gateway_connection, connection_id, &remote_host);
                            break false;
                        }
                    }
                }
                _ = reset.cancelled() => break true,
            },
            None => tokio::select! {
                // Data already in the socket is read before the flag is looked at.
                biased;
                read_result = read.read_buf(&mut buf) => read_result,
                _ = disconnected.cancelled() => {
                    if gateway_connection.has_forward_connection(connection_id) {
                        write_failed_at = Some(tokio::time::Instant::now());
                        continue;
                    }
                    break true;
                }
            },
        };

        let read_size = match read_result {
            Ok(read_size) => read_size,
            Err(err) => {
                let dt = gateway_connection.get_connection_timestamp();
                let err = format!(
                    "Gateway:[{}]. ReadLoop. Can not read from connection {} with id {connection_id} created at: {} ConnectionError: {:?}",
                    gateway_connection.get_gateway_id(),
                    remote_host.as_str(),
                    dt.to_rfc3339(),
                    err
                );
                crate::tcp_gateway::scripts::end_forward_connection(
                    gateway_connection.as_ref(),
                    connection_id,
                    &remote_host,
                    ConnectionEnd::Reset(&err),
                );
                break false;
            }
        };

        if read_size == 0 {
            // The upstream closed its side. A write still on its way to it may fail now - on Linux
            // an upstream which reset reads as a plain EOF once the writer has taken the reset -
            // and then what the peer sent did not all arrive: the close has to say so.
            if write_failed_at.is_some() || writer_failed(&write).await {
                close_after_write_failure(&gateway_connection, connection_id, &remote_host);
                break false;
            }

            crate::tcp_gateway::scripts::end_forward_connection(
                gateway_connection.as_ref(),
                connection_id,
                &remote_host,
                ConnectionEnd::Closed,
            );
            break false;
        }

        let payload = &buf[..read_size];

        let sent = match drain_deadline {
            Some(deadline) => {
                let send = gateway_connection.send_backward_payload(connection_id, payload);
                tokio::select! {
                    biased;
                    sent = tokio::time::timeout_at(deadline, send) => match sent {
                        Ok(sent) => sent,
                        Err(_) => {
                            close_after_write_failure(&gateway_connection, connection_id, &remote_host);
                            break false;
                        }
                    },
                    _ = reset.cancelled() => break true,
                }
            }
            None => tokio::select! {
                biased;
                sent = gateway_connection.send_backward_payload(connection_id, payload) => sent,
                _ = disconnected.cancelled() => {
                    if !gateway_connection.has_forward_connection(connection_id) {
                        break true;
                    }

                    // Only the write to the upstream failed: this chunk still goes out, within the
                    // drain limit.
                    let failed_at = tokio::time::Instant::now();
                    write_failed_at = Some(failed_at);

                    let send = gateway_connection.send_backward_payload(connection_id, payload);
                    tokio::select! {
                        biased;
                        sent = tokio::time::timeout_at(failed_at + WRITE_FAILED_DRAIN_LIMIT, send) => match sent {
                            Ok(sent) => sent,
                            Err(_) => {
                                close_after_write_failure(&gateway_connection, connection_id, &remote_host);
                                break false;
                            }
                        },
                        _ = reset.cancelled() => break true,
                    }
                }
            },
        };

        // Not sent: the peer closed the connection, or the gateway connection is gone.
        if !sent {
            break true;
        }
    };

    if peer_gone && !write.is_reset() {
        // The peer closed the connection: there is nobody to forward to, but the writer may still
        // be flushing what the peer sent before.
        linger(&mut read, &write).await;
    }

    // Also after a linger cut short by a reset: the connection may be unregistered a moment
    // before it is reset.
    if write.is_reset() {
        // The writer gives its half up without shutting it down: the socket closes with a reset,
        // whichever half goes last.
        read.reset_on_close();
    }
}

/// How long the upstream is still read and forwarded after a write to it failed.
const WRITE_FAILED_DRAIN_LIMIT: Duration = Duration::from_secs(5);

/// How long the read loop waits for the writer, once the upstream closed its side, before it tells
/// the peer how the connection ended.
const WRITER_OUTCOME_WAIT: Duration = Duration::from_secs(2);

/// Closes the writer and lets it hand the upstream what it still holds - for
/// [`WRITER_OUTCOME_WAIT`] at most - then tells whether a write to the upstream failed.
async fn writer_failed(write: &TcpConnectionInner) -> bool {
    write.disconnect();

    let writer_finished = write.writer_finished_token();
    let _ = tokio::time::timeout(WRITER_OUTCOME_WAIT, writer_finished.cancelled()).await;

    write.write_failed()
}

/// Resets the connection after the write to the upstream failed and what the upstream sent after
/// it was forwarded: the peer's reader gets an error, since what it sent did not all arrive.
fn close_after_write_failure(
    gateway_connection: &TcpGatewayConnection,
    connection_id: u32,
    remote_host: &str,
) {
    let err = format!("ReadLoop. Connection to {remote_host} with id:{connection_id} is lost");

    crate::tcp_gateway::scripts::end_forward_connection(
        gateway_connection,
        connection_id,
        remote_host,
        ConnectionEnd::Reset(&err),
    );
}

/// How long the upstream may take to close its side once the writer is done with it.
const LINGER_AFTER_FLUSH: Duration = Duration::from_secs(2);

/// The longest the read side is kept for a writer still flushing - the writer itself gives up on
/// its flush after 30 seconds.
const LINGER_LIMIT: Duration = Duration::from_secs(35);

/// Keeps reading the upstream - and dropping what it sends - until the writer has handed it the
/// last bytes and shut the socket's write side down, then a moment longer, for the upstream to
/// close its side first. Closing a socket with unread data in it resets the connection, and a
/// reset can make the upstream discard the tail it was just sent. Not once the connection is
/// reset: then there is no tail to protect.
async fn linger(read: &mut MyOwnedReadHalf, write: &TcpConnectionInner) {
    let writer_finished = write.writer_finished_token();
    let reset = write.reset_token();
    let mut scratch = vec![0u8; 16 * 1024];

    let drain = async {
        // Ends once the upstream has closed its side: nothing more can arrive to be left unread.
        while let Ok(read_size) = read.read(&mut scratch).await {
            if read_size == 0 {
                break;
            }
        }
    };

    let writer_done = async {
        writer_finished.cancelled().await;
        tokio::time::sleep(LINGER_AFTER_FLUSH).await;
    };

    let _ = tokio::time::timeout(LINGER_LIMIT, async {
        tokio::select! {
            _ = drain => {}
            _ = writer_done => {}
            _ = reset.cancelled() => {}
        }
    })
    .await;
}

async fn connect_to_tcp_socket(
    remote_endpoint: &str,
    connection_id: u32,
    timeout: Duration,
) -> Result<MyNetworkStream, String> {
    let connect_future = tokio::net::TcpStream::connect(remote_endpoint);

    let result = tokio::time::timeout(timeout, connect_future).await;

    let Ok(result) = result else {
        return Err(format!(
            "Can not connect to tcp-socket {} with id {}. Err: Timeout {:?}",
            remote_endpoint, connection_id, timeout
        ));
    };

    match result {
        Ok(tcp_stream) => Ok(MyNetworkStream::Tcp(tcp_stream)),
        Err(err) => Err(format!(
            "Can not connect to tcp-socket {} with id {}. Err: {:?}",
            remote_endpoint, connection_id, err
        )),
    }
}

async fn connect_to_unix_socket(
    remote_endpoint: &str,
    connection_id: u32,
    timeout: Duration,
) -> Result<MyNetworkStream, String> {
    let connect_future = tokio::net::UnixStream::connect(remote_endpoint);

    let result = tokio::time::timeout(timeout, connect_future).await;

    let Ok(result) = result else {
        return Err(format!(
            "Can not connect to unix socket {} with id {}. Err: Timeout {:?}",
            remote_endpoint, connection_id, timeout
        ));
    };

    match result {
        Ok(tcp_stream) => Ok(MyNetworkStream::UnixSocket(tcp_stream)),
        Err(err) => Err(format!(
            "Can not connect to unix socket {} with id {}. Err: {:?}",
            remote_endpoint, connection_id, err
        )),
    }
}
