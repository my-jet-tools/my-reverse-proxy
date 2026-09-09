use std::{fmt::Debug, sync::Arc};

use my_tls::tokio_rustls::rustls;

use rustls::{
    crypto::WebPkiSupportedAlgorithms, server::danger::ClientCertVerifier, SignatureScheme,
};

use super::{client_cert_cell::ClientCertCell, ClientCertificateCa};

pub struct MyClientCertVerifier {
    client_cert_cell: Arc<ClientCertCell>,
    pub ca: Arc<ClientCertificateCa>,
    /// `client_certificate_id` this verifier was built for — stamped into the
    /// produced [`ClientCertificateData`] so per-endpoint checks can tell which
    /// CA actually verified the connection's certificate.
    ca_id: String,
    endpoint_port: u16,
    /// The signature algorithms the crypto provider can actually verify. Used both to tell the
    /// client which schemes its certificate may sign with, and to check the CertificateVerify
    /// message it sends back.
    supported_algs: WebPkiSupportedAlgorithms,
}

impl MyClientCertVerifier {
    pub fn new(
        client_cert_cell: Arc<ClientCertCell>,
        ca: Arc<ClientCertificateCa>,
        ca_id: String,
        endpoint_port: u16,
    ) -> Self {
        // `main` installs the provider before anything listens; the ring default is only a
        // fallback so this can never end up with no algorithms (which would reject every client).
        let supported_algs = match rustls::crypto::CryptoProvider::get_default() {
            Some(provider) => provider.signature_verification_algorithms,
            None => rustls::crypto::ring::default_provider().signature_verification_algorithms,
        };

        Self {
            ca,
            client_cert_cell,
            ca_id,
            endpoint_port,
            supported_algs,
        }
    }
}

impl Debug for MyClientCertVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MyClientCertVerifier")
            .field("server_id", &self.endpoint_port)
            .finish()
    }
}

impl ClientCertVerifier for MyClientCertVerifier {
    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        self.ca.get_names()
    }

    /// PROOF OF POSSESSION. Without this check a client only has to PRESENT a certificate, never
    /// to hold its private key — so anyone with a copy of someone else's client certificate (or of
    /// the CA certificate, which verifies against itself) would authenticate. rustls performs no
    /// signature check of its own here: whatever this returns is the verdict.
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls_pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.supported_algs)
    }

    /// See [`Self::verify_tls12_signature`] — the same proof of possession, for TLS 1.3.
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls_pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<
        my_tls::tokio_rustls::rustls::client::danger::HandshakeSignatureValid,
        my_tls::tokio_rustls::rustls::Error,
    > {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.supported_algs)
    }

    /// What goes into the CertificateRequest as the acceptable signature algorithms. Advertising
    /// a single scheme (this used to say RSA_PSS_SHA256 only) tells every conforming client that
    /// its ECDSA / Ed25519 / RSA-PKCS1 certificate is unusable, so it sends none and the handshake
    /// fails — the provider's full list is what the verification above can actually check.
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.supported_algs.supported_schemes()
    }

    fn verify_client_cert(
        &self,
        end_entity: &rustls_pki_types::CertificateDer<'_>,
        _intermediates: &[rustls_pki_types::CertificateDer<'_>],
        now: rustls_pki_types::UnixTime,
    ) -> Result<
        my_tls::tokio_rustls::rustls::server::danger::ClientCertVerified,
        my_tls::tokio_rustls::rustls::Error,
    > {
        if let Some(client_certificate) = self.ca.verify_cert(end_entity, self.ca_id.as_str(), now)
        {
            self.client_cert_cell.set(client_certificate);

            return Ok(
                my_tls::tokio_rustls::rustls::server::danger::ClientCertVerified::assertion(),
            );
        }

        Err(my_tls::tokio_rustls::rustls::Error::General(
            "Client certificate is not valid".to_string(),
        ))
    }
}
