//! What keeps the proxy's secrets. The store on its disk, encrypted with the files key that
//! `POST /api/initialize` brings after every start, and the network keys every packet of the
//! standard is encrypted with (`Content-Encoding: aes128gcm`, RFC 8188 - my-http-utils' and
//! my-http-server's implementation).
//!
//! docs/secure-parameters.md is the proxy's side of it; docs/encrypted-service-data.md is what a
//! service does to serve the proxy encrypted data.

mod keys;
pub use keys::*;

mod secure_store;
pub use secure_store::*;

mod secure_state;
pub use secure_state::*;

mod private_keys;
pub use private_keys::*;

#[cfg(test)]
mod reading_tests;
