use std::sync::Arc;

use tokio::sync::mpsc;

use crate::network_stream::*;

use super::{InFlightResponses, ResponseEvent, ResponseSlot};

/// The single owner of the client write half. It drains an ordered queue of
/// response slots (FIFO = response order) and writes each slot's events to the
/// client to completion before taking the next slot. Because it is the sole
/// writer, there is no shared mutex on the socket — ordering is structural (the
/// queue), not bookkept.
///
/// Returns `Some(write_part)` when the queue closes cleanly (the reader dropped
/// its sender with no in-flight failure) — the connection entry takes the write
/// half back to build a websocket tunnel. Returns `None` when the connection had
/// to be closed (write failure, aborted or incomplete response): the write half
/// has been shut down and must not be reused.
pub async fn run_client_writer<WritePart: NetworkStreamWritePart + Send + Sync + 'static>(
    mut write_part: WritePart,
    mut queue: mpsc::Receiver<ResponseSlot>,
    in_flight: Arc<InFlightResponses>,
) -> Option<WritePart> {
    while let Some(mut slot) = queue.recv().await {
        let metered = slot.access.is_some();
        let mut meter = AnswerMeter::default();

        let end = loop {
            let Some(event) = slot.events.recv().await else {
                break AnswerEnd::WorkerGone;
            };

            match event {
                ResponseEvent::Chunk(bytes) => {
                    if write_part
                        .write_all_with_timeout(&bytes, slot.write_timeout)
                        .await
                        .is_err()
                    {
                        break AnswerEnd::ClientGone;
                    }

                    if metered {
                        meter.passed(&bytes);
                    }
                }
                ResponseEvent::Done => break AnswerEnd::Whole,
                ResponseEvent::Abort => break AnswerEnd::Aborted,
            }
        };

        if let Some(access) = slot.access.take() {
            access.answered(
                meter.status,
                meter.body_bytes,
                matches!(end, AnswerEnd::Whole),
            );
        }

        match end {
            // Written out: if it was the last one, the wait for the client's next
            // request starts now.
            AnswerEnd::Whole => in_flight.finished(),
            // Client gone — abandon the whole connection.
            AnswerEnd::ClientGone => return None,
            // Response truncated mid-stream - or the worker dropped its sender
            // without Done/Abort (it died): the only correct H1 move is to close
            // the connection rather than serve the next slot on a desynced one.
            AnswerEnd::Aborted | AnswerEnd::WorkerGone => {
                write_part.shutdown_socket().await;
                return None;
            }
        }
    }

    let _ = write_part.flush_it().await;
    Some(write_part)
}

/// How the writing of one answer ended.
enum AnswerEnd {
    Whole,
    ClientGone,
    Aborted,
    WorkerGone,
}

/// What the access log tells of an answer as it goes out: its status, and the bytes of its body.
#[derive(Default)]
struct AnswerMeter {
    status: u16,
    body_bytes: u64,
    /// The final head is out: what comes next is the body. An interim `1xx` head comes first.
    head_out: bool,
}

impl AnswerMeter {
    fn passed(&mut self, bytes: &[u8]) {
        if self.head_out {
            self.body_bytes += bytes.len() as u64;
            return;
        }

        let Some(status) = status_of_head(bytes) else {
            return;
        };

        self.status = status;

        if (100..200).contains(&status) {
            return;
        }

        self.head_out = true;

        let head_end = bytes
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .map_or(bytes.len(), |pos| pos + 4);
        self.body_bytes += (bytes.len() - head_end) as u64;
    }
}

/// The status of a head which starts `bytes` - `HTTP/1.1 200 OK`.
fn status_of_head(bytes: &[u8]) -> Option<u16> {
    let rest = bytes.strip_prefix(b"HTTP/1.")?.get(2..5)?;
    std::str::from_utf8(rest).ok()?.parse().ok()
}

#[cfg(test)]
mod answer_meter_tests {
    use super::*;

    #[test]
    fn the_status_is_of_the_final_head_and_the_bytes_of_the_body() {
        let mut meter = AnswerMeter::default();

        meter.passed(b"HTTP/1.1 100 Continue\r\n\r\n");
        assert_eq!(meter.status, 100);

        meter.passed(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n01234");
        meter.passed(b"56789");

        assert_eq!(meter.status, 200);
        assert_eq!(meter.body_bytes, 10);
    }

    #[test]
    fn a_page_of_one_piece_is_its_head_and_its_body() {
        let mut meter = AnswerMeter::default();
        meter.passed(
            b"HTTP/1.1 431 Request Header Fields Too Large\r\nContent-Length: 4\r\n\r\npage",
        );

        assert_eq!(meter.status, 431);
        assert_eq!(meter.body_bytes, 4);
    }
}
