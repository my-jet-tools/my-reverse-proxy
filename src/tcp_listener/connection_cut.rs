use std::{
    future::Future,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

use tokio::sync::Notify;

/// How long a request which cut its connection waits for the connection to be gone. Past it the
/// request ends anyway - its answer goes nowhere: the connection is cut.
const CUT_GRACE: Duration = Duration::from_secs(5);

/// Closes a connection served by hyper (`http2` and `https2` endpoints) from inside one of its
/// requests, without a word: a request of hyper can only answer, and an answer is a word.
///
/// The connection is served through [`ConnectionCut::serve`]; a request which finds it must not
/// go on calls [`ConnectionCut::cut_now`], and the connection is dropped - closed - before the
/// request ends, so nothing it would answer is sent. Every other request of the connection - an
/// h2 one carries several at once - ends with it.
pub struct ConnectionCut {
    cut: AtomicBool,
    cut_notify: Notify,
    closed: AtomicBool,
    closed_notify: Notify,
}

impl ConnectionCut {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            cut: AtomicBool::new(false),
            cut_notify: Notify::new(),
            closed: AtomicBool::new(false),
            closed_notify: Notify::new(),
        })
    }

    /// Serves `connection` to its end - or drops it, which closes it, once a request cut it:
    /// `None` then. The cut is looked at first, so a connection which was cut is not given another
    /// turn to write what a request answered.
    pub async fn serve<TConnection: Future>(
        &self,
        connection: TConnection,
    ) -> Option<TConnection::Output> {
        let result = tokio::select! {
            biased;
            _ = wait(&self.cut, &self.cut_notify) => None,
            output = connection => Some(output),
        };

        self.closed.store(true, Ordering::Release);
        self.closed_notify.notify_waiters();

        result
    }

    /// Cuts the connection, and waits until it is gone (at most [`CUT_GRACE`]). The request which
    /// calls it answers nothing anybody gets.
    pub async fn cut_now(&self) {
        self.cut.store(true, Ordering::Release);
        self.cut_notify.notify_waiters();

        let _ = tokio::time::timeout(CUT_GRACE, wait(&self.closed, &self.closed_notify)).await;
    }

    #[cfg(test)]
    pub fn is_cut(&self) -> bool {
        self.cut.load(Ordering::Acquire)
    }
}

/// Until `flag` is set - by whoever sets it and then notifies the waiters of `notify`.
async fn wait(flag: &AtomicBool, notify: &Notify) {
    let notified = notify.notified();
    tokio::pin!(notified);
    // Registered before the flag is read: a set between the read and the wait is not missed.
    notified.as_mut().enable();

    if flag.load(Ordering::Acquire) {
        return;
    }

    notified.await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_cut_drops_the_connection_before_the_request_ends() {
        let cut = ConnectionCut::new();
        let request_cut = cut.clone();

        // The connection: a request which cuts it, and then would answer.
        let answered = Arc::new(AtomicBool::new(false));
        let answered_by_the_request = answered.clone();
        let connection = async move {
            request_cut.cut_now().await;
            answered_by_the_request.store(true, Ordering::Release);
        };

        let result = tokio::time::timeout(Duration::from_secs(1), cut.serve(connection))
            .await
            .expect("a cut connection is still served");

        assert!(result.is_none());
        assert!(cut.is_cut());
        assert!(
            !answered.load(Ordering::Acquire),
            "the request went on after the connection was cut"
        );
    }

    #[tokio::test]
    async fn a_request_on_a_task_of_its_own_ends_once_the_connection_is_gone() {
        let cut = ConnectionCut::new();

        // An h2 request runs on a task of its own, not inside the connection.
        let request = tokio::spawn({
            let cut = cut.clone();
            async move { cut.cut_now().await }
        });

        let result = cut.serve(std::future::pending::<()>()).await;
        assert!(result.is_none());

        tokio::time::timeout(Duration::from_secs(1), request)
            .await
            .expect("the request waited out the whole grace")
            .unwrap();
    }

    #[tokio::test]
    async fn a_connection_which_is_not_cut_is_served_to_its_end() {
        let cut = ConnectionCut::new();

        assert_eq!(cut.serve(async { 42 }).await, Some(42));
        assert!(!cut.is_cut());
    }
}
