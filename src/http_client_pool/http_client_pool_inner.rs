use std::{collections::HashMap, time::Duration};

use my_http_client::{http1::MyHttpClient, MyHttpClientConnector};
use parking_lot::Mutex;
use rust_extensions::date_time::DateTimeAsMicroseconds;

/// Idle clients by remote endpoint, each with the moment it was returned to the pool.
type IdleClients<TStream, TConnector> =
    HashMap<String, Vec<(DateTimeAsMicroseconds, MyHttpClient<TStream, TConnector>)>>;

pub struct HttpClientPoolInner<
    TStream: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Sync + 'static,
    TConnector: MyHttpClientConnector<TStream> + Send + Sync + 'static,
> {
    items: Mutex<IdleClients<TStream, TConnector>>,
}

impl<
        TStream: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Sync + 'static,
        TConnector: MyHttpClientConnector<TStream> + Send + Sync + 'static,
    > HttpClientPoolInner<TStream, TConnector>
{
    pub fn new() -> Self {
        Self {
            items: Mutex::new(HashMap::new()),
        }
    }

    pub fn get_or_create(
        &self,
        remote_endpoint: &str,
        connect_timeout: Duration,
        read_timeout: Option<Duration>,
        create_connector: impl FnOnce() -> TConnector,
    ) -> MyHttpClient<TStream, TConnector> {
        let mut items_access = self.items.lock();

        if let Some(client) = items_access
            .get_mut(remote_endpoint)
            .and_then(|pool| pool.pop())
        {
            return client.1;
        }

        let mut client = MyHttpClient::new(create_connector());
        client.set_connect_timeout(connect_timeout);
        if let Some(read_timeout) = read_timeout {
            client.set_read_from_stream_timeout(read_timeout);
        }
        client
    }

    /// Adds this pool's idle clients to `dest`, summing with what other pools put under the
    /// same key.
    pub fn fill_connections_amount(&self, dest: &mut HashMap<String, usize>) {
        let items = self.items.lock();
        for (key, value) in items.iter() {
            if !value.is_empty() {
                *dest.entry(key.clone()).or_insert(0) += value.len();
            }
        }
    }

    pub fn gc(&self) {
        let now = DateTimeAsMicroseconds::now();
        let mut items_access = self.items.lock();

        for v in items_access.values_mut() {
            while !v.is_empty() {
                let first = v.first().unwrap().0;
                if now.duration_since(first).get_full_minutes() > 2 {
                    v.remove(0);
                } else {
                    break;
                }
            }

            if v.len() < 32 {
                v.shrink_to(32);
            }
        }
    }

    pub fn return_back(
        &self,
        remote_endpoint: String,
        my_http_client: MyHttpClient<TStream, TConnector>,
    ) {
        let now = DateTimeAsMicroseconds::now();
        let mut items_access = self.items.lock();

        match items_access.get_mut(remote_endpoint.as_str()) {
            Some(pool) => pool.push((now, my_http_client)),
            None => {
                items_access.insert(remote_endpoint, vec![(now, my_http_client)]);
            }
        }
    }
}
