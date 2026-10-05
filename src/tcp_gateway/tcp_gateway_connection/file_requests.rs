use std::collections::HashMap;

use parking_lot::Mutex;
use rust_extensions::{TaskCompletion, TaskCompletionAwaiter};

pub enum FileRequestError {
    FileNotFound,
    GatewayDisconnected,
    Timeout,
}

#[derive(Default)]
pub struct FileRequestsInner {
    requests: HashMap<u32, TaskCompletion<Vec<u8>, FileRequestError>>,
    next_request_id: u32,
}

impl FileRequestsInner {
    pub fn get_next_request_id(&mut self) -> u32 {
        self.next_request_id = self.next_request_id.wrapping_add(1);
        self.next_request_id
    }
}

pub struct FileRequests {
    inner: Mutex<FileRequestsInner>,
}

impl FileRequests {
    pub fn new() -> Self {
        Self {
            inner: Mutex::default(),
        }
    }

    pub fn start_request(&self) -> (TaskCompletionAwaiter<Vec<u8>, FileRequestError>, u32) {
        let mut task_completion = TaskCompletion::new();
        task_completion.set_drop_error(FileRequestError::GatewayDisconnected);
        let awaiter = task_completion.get_awaiter();
        let mut write_access = self.inner.lock();
        let request_id = write_access.get_next_request_id();
        write_access.requests.insert(request_id, task_completion);

        (awaiter, request_id)
    }

    pub fn set_content(&self, request_id: u32, content: Vec<u8>) {
        let item = {
            let mut write_access = self.inner.lock();
            write_access.requests.remove(&request_id)
        };

        if let Some(mut item) = item {
            let _ = item.try_set_ok(content);
        }
    }

    pub fn set_error(&self, request_id: u32, error: FileRequestError) {
        let item = {
            let mut write_access = self.inner.lock();
            write_access.requests.remove(&request_id)
        };

        if let Some(mut item) = item {
            let _ = item.try_set_error(error);
        }
    }

    /// Forgets a request nobody waits for any more. A dropped request completes with its drop
    /// error, `GatewayDisconnected`.
    pub fn remove_request(&self, request_id: u32) {
        let item = {
            let mut write_access = self.inner.lock();
            write_access.requests.remove(&request_id)
        };

        drop(item);
    }

    /// Fails every pending request with `GatewayDisconnected`: the gateway connection which
    /// would carry the answers is gone.
    pub fn fail_all(&self) {
        let requests = {
            let mut write_access = self.inner.lock();
            std::mem::take(&mut write_access.requests)
        };

        drop(requests);
    }
}

/// Removes a request from the registry when whoever waits for it stops waiting - it timed out,
/// or its caller was dropped. An answer removes the request as well, so this is then a no-op.
pub struct PendingFileRequest<'s> {
    pub requests: &'s FileRequests,
    pub request_id: u32,
}

impl Drop for PendingFileRequest<'_> {
    fn drop(&mut self) {
        self.requests.remove_request(self.request_id);
    }
}
