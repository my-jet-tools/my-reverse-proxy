//mod http;

mod http2;

pub mod https;

//mod handle_request;
//pub use generate_tech_page::*;
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
mod h1_malformed_request_tests;

#[cfg(test)]
mod strip_path_tests;
