//mod http;

mod http2;
mod plain_http;

pub mod https;

//mod handle_request;
//pub use generate_tech_page::*;
mod first_request_deadline;
pub use first_request_deadline::*;
mod connection_cut;
pub use connection_cut::*;
mod connection_lifetime;
pub use connection_lifetime::*;
mod watched_response;
pub use watched_response::*;
mod listen_server_handler;
pub use listen_server_handler::*;
mod listen_tcp_server;
pub use listen_tcp_server::*;
mod http_request_handler;
#[cfg(unix)]
mod listen_unix_server;
pub mod mcp;
mod tcp_port_forward;
#[cfg(unix)]
pub use listen_unix_server::*;

#[cfg(test)]
mod files_location_tests;

#[cfg(test)]
mod location_whitelist_tests;

#[cfg(test)]
mod ambiguous_path_tests;

#[cfg(test)]
mod api_keys_tests;

#[cfg(test)]
mod h1_malformed_request_tests;

#[cfg(test)]
mod strip_path_tests;

#[cfg(test)]
mod accept_loop_tests;

#[cfg(test)]
mod slow_client_tests;

#[cfg(test)]
mod h1_to_h2_upstream_tests;

#[cfg(test)]
mod plain_http_tests;

#[cfg(all(test, unix))]
mod unix_socket_mcp_tests;
