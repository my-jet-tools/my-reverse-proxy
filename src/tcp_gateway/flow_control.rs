//! Per-connection flow control: each direction of a tunnelled connection has a credit window, so
//! its receiving end holds at most the window it advertised, however slow its reader or target.
//! See "Flow control" in docs/gateway-protocol.md.

use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

use tokio::sync::Semaphore;

use super::{TcpConnectionInner, TcpGatewayContract, MAX_PAYLOAD_CHUNK};

/// The receive window this side advertises, per tunnelled connection and direction - and the most
/// payload it then holds for that direction. It travels on the wire, so changing it (at or above
/// [`MIN_RECEIVE_WINDOW`]) needs no coordinated upgrade of the peers.
pub const FLOW_CONTROL_WINDOW: usize = 8 * 1024 * 1024;

/// Payload the consumer has taken before it is credited back in one `WINDOW_UPDATE`.
pub const FLOW_CONTROL_UPDATE_THRESHOLD: usize = 512 * 1024;

/// Protocol rule: the least window either end may advertise. A `CONNECT` with a smaller window is
/// refused, and a connect whose credit at `CONNECT_OK` is smaller fails - under it a chunk might
/// never fit, and the sender would stall without a word.
pub const MIN_RECEIVE_WINDOW: usize = 1024 * 1024;

/// Where held credit saturates. A compliant peer's outstanding grant never exceeds the window it
/// advertised, a `u32`, so this only keeps a broken peer from overflowing the semaphore.
pub const MAX_SEND_CREDIT: usize = if (u32::MAX as usize) < Semaphore::MAX_PERMITS {
    u32::MAX as usize
} else {
    Semaphore::MAX_PERMITS
};

// Our receiver keeps the protocol rule even at the floor: it credits before it holds back
// `window - MAX_PAYLOAD_CHUNK`, so a sender's request always fits once the consumer caught up.
const _: () = assert!(FLOW_CONTROL_UPDATE_THRESHOLD + MAX_PAYLOAD_CHUNK <= MIN_RECEIVE_WINDOW);
const _: () = assert!(MIN_RECEIVE_WINDOW <= FLOW_CONTROL_WINDOW);
const _: () = assert!(FLOW_CONTROL_WINDOW <= u32::MAX as usize);

/// Accounting of one receiving direction of a tunnelled connection.
#[derive(Default)]
pub struct ReceiveCounter {
    /// Received, not yet taken by the consumer.
    held: AtomicUsize,
    /// Taken by the consumer, not yet credited back.
    owed: AtomicUsize,
}

impl ReceiveCounter {
    /// A payload of `len` bytes arrived. `false`: the sender went past the window this side
    /// advertised.
    pub fn received(&self, len: usize) -> bool {
        self.held.fetch_add(len, Ordering::AcqRel) + len <= FLOW_CONTROL_WINDOW
    }

    /// The consumer took `len` bytes. Returns the credit to send once at least
    /// [`FLOW_CONTROL_UPDATE_THRESHOLD`] is owed; every byte is credited exactly once.
    pub fn consumed(&self, len: usize) -> Option<u32> {
        // Lowered before the credit goes out: payload the peer sends on the strength of it must
        // find `held` down already.
        self.held.fetch_sub(len, Ordering::AcqRel);

        if self.owed.fetch_add(len, Ordering::AcqRel) + len < FLOW_CONTROL_UPDATE_THRESHOLD {
            return None;
        }

        // Below THRESHOLD + WINDOW: fits a u32.
        let credit = self.owed.swap(0, Ordering::AcqRel);
        (credit > 0).then_some(credit as u32)
    }

    #[cfg(test)]
    pub fn held(&self) -> usize {
        self.held.load(Ordering::Acquire)
    }
}

/// The accounting of one receiving direction, and where its credit goes. No `Arc` cycle: it holds
/// the gateway peer's writer, which references no connection.
pub struct ReceiveWindow {
    connection_id: u32,
    gateway: Arc<TcpConnectionInner>,
    counter: ReceiveCounter,
}

impl ReceiveWindow {
    pub fn new(connection_id: u32, gateway: Arc<TcpConnectionInner>) -> Self {
        Self {
            connection_id,
            gateway,
            counter: ReceiveCounter::default(),
        }
    }

    /// A payload of `len` bytes arrived. `false`: the sender went past the window.
    pub fn received(&self, len: usize) -> bool {
        self.counter.received(len)
    }

    /// The consumer took `len` bytes - the proxy stream's reader read them, or the raw writer
    /// wrote them to the target. Never waits: `WINDOW_UPDATE` takes no write budget and goes out
    /// with the writer's next batch. Never called by a gateway read loop.
    pub fn consumed(&self, len: usize) {
        if let Some(credit) = self.counter.consumed(len) {
            let frame = TcpGatewayContract::WindowUpdate {
                connection_id: self.connection_id,
                credit,
            }
            .to_plain_frame();

            // `false` once the gateway connection is gone - the connection with it.
            self.gateway.send_expedited(frame);
        }
    }

    #[cfg(test)]
    pub fn held(&self) -> usize {
        self.counter.held()
    }
}

/// Adds the peer's credit to a send window, saturating at [`MAX_SEND_CREDIT`] - which no compliant
/// peer reaches, so all the credit a peer grants is used.
pub fn add_credit(window: &Semaphore, credit: u32) {
    let room = MAX_SEND_CREDIT.saturating_sub(window.available_permits());
    window.add_permits((credit as usize).min(room));
}

/// The protocol floor, checked by the initiator at `CONNECT_OK` on the credit it got by then.
pub fn initial_credit_is_enough(credit: usize) -> bool {
    credit >= MIN_RECEIVE_WINDOW
}
