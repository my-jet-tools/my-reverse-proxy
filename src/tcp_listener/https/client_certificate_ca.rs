use std::sync::Arc;

use my_ssh::ssh_settings::OverSshConnectionSettings;

use rust_extensions::date_time::DateTimeAsMicroseconds;
use rustls_pki_types::CertificateDer;
use x509_parser::{certificate::X509Certificate, der_parser::asn1_rs::FromDer};

use my_tls::{crl::CrlRecord, tokio_rustls::rustls};

#[derive(Debug, Clone)]
pub struct ClientCertificateData {
    pub cn: String,
    /// `client_certificate_id` of the CA this certificate was verified against
    /// during the TLS handshake. A connection may carry requests for other
    /// vhosts (HTTP/2 coalescing, keep-alive cross-`Host` reuse), so every
    /// per-endpoint decision must check that the endpoint requires THIS CA —
    /// the CN below means nothing to an endpoint trusting a different CA.
    pub ca_id: String,
    /// The certificate was outside its validity window and was accepted anyway, because the
    /// endpoint that opened this connection declares `unlimited_expiration`. Another endpoint
    /// sharing the same ca but NOT declaring it must refuse requests carried over this
    /// connection - the escape hatch belongs to the endpoint that opted into it.
    pub accepted_outside_validity: bool,
}

/// Metadata of the CA certificate a client-certificate id is currently loaded with.
/// Metadata only — the CA PEM material itself is never handed out.
#[derive(Debug, Clone)]
pub struct ClientCertificateCaInfo {
    pub cn: String,
    pub expires: DateTimeAsMicroseconds,
    /// `true` when the certificate carries BasicConstraints CA:TRUE. A self-signed leaf used
    /// directly as the trust anchor (which this verifier accepts) reports `false` — it is shown
    /// to the operator, not enforced.
    pub is_ca: bool,
}

pub struct ClientCertificateCa {
    ca_content: CertificateDer<'static>,
    names: Vec<rustls::DistinguishedName>,
    /// Where the CA came from. `None` for a CA uploaded at runtime from the admin ui or
    /// /api/ClientCertificates/Init(FromPem) — there is no source to re-read or refresh from.
    pub ca_file_source: Option<OverSshConnectionSettings>,
    pub crl_list: Vec<CrlRecord>,
    pub crl_file_source: Option<OverSshConnectionSettings>,
}

impl ClientCertificateCa {
    pub fn from_bytes(
        value: &[u8],
        file_source: Option<OverSshConnectionSettings>,
        crl: Option<(Vec<CrlRecord>, Option<OverSshConnectionSettings>)>,
    ) -> Result<Self, String> {
        let mut reader = std::io::BufReader::new(value);

        let certs = rustls_pemfile::certs(&mut reader);

        // Load and return certificate.
        let mut result = Vec::new();

        for cert in certs {
            // The PEM can come from an operator upload, so a broken block is an error to report,
            // never a panic.
            let cert =
                cert.map_err(|err| format!("Error loading client CA certificate: {}", err))?;
            result.push(cert);
        }

        if let Some(crl) = crl {
            Self::new(result, file_source, crl.0, crl.1)
        } else {
            Self::new(result, file_source, vec![], None)
        }
    }
    pub fn new(
        mut certs: Vec<CertificateDer<'static>>,
        ca_file_source: Option<OverSshConnectionSettings>,
        crl_list: Vec<CrlRecord>,
        crl_file_source: Option<OverSshConnectionSettings>,
    ) -> Result<Self, String> {
        if certs.is_empty() {
            return Err("No certificate found in the provided client CA PEM content".to_string());
        }

        let mut names = Vec::new();

        for ca in &certs {
            let (_, cert) = X509Certificate::from_der(ca)
                .map_err(|err| format!("Can not parse client CA certificate: {}", err))?;

            // These DNs go out in the CertificateRequest as `certificate_authorities` - the
            // acceptable ISSUERS of the client certificate, which for a trust anchor is the
            // anchor's own SUBJECT. Sending its issuer instead only coincides for a self-signed
            // root; for an intermediate it makes conforming clients select no certificate at all.
            names.push(cert.subject().as_raw().to_vec().into());
        }

        let resut = Self {
            ca_content: certs.remove(0),
            names,
            ca_file_source,
            crl_list,
            crl_file_source,
        };

        Ok(resut)
    }

    /// Verifies a client certificate against this trust anchor.
    ///
    /// `check_validity_at` is the handshake time rustls provides - the certificate's own validity
    /// window is enforced against it, because expiry is how most deployments retire a client
    /// certificate (a CRL is optional, and often absent). It is `None` only when the ca is
    /// declared `unlimited_expiration: true` in the configuration, which is the operator saying
    /// "accept these certificates however old they are". Returns `None` for every rejection.
    pub fn verify_cert(
        &self,
        certificate_to_check: &rustls_pki_types::CertificateDer,
        ca_id: &str,
        check_validity_at: Option<rustls_pki_types::UnixTime>,
    ) -> Option<Arc<ClientCertificateData>> {
        // Both sides are parsed defensively: `certificate_to_check` is whatever the client put
        // into the TLS handshake, so an unparseable certificate must be rejected, not panic the
        // connection task.
        let (_, issuer) = X509Certificate::from_der(self.ca_content.as_ref()).ok()?;

        let (_, cert_to_check) = X509Certificate::from_der(certificate_to_check.as_ref()).ok()?;

        let cn = cert_to_check
            .subject()
            .iter_common_name()
            .next()
            .and_then(|cn| cn.as_str().ok())
            .unwrap_or_default()
            .to_string();

        let accepted_outside_validity = match check_validity_at {
            Some(now) => {
                let now =
                    x509_parser::prelude::ASN1Time::from_timestamp(now.as_secs() as i64).ok()?;

                if !cert_to_check.validity().is_valid_at(now) {
                    return None;
                }

                false
            }
            None => {
                // Expiry is not enforced here, but WHETHER it would have failed is recorded on the
                // connection: a stricter endpoint reached over the same connection has to be able
                // to refuse it.
                let now = rust_extensions::date_time::DateTimeAsMicroseconds::now();
                match x509_parser::prelude::ASN1Time::from_timestamp(
                    now.unix_microseconds / 1_000_000,
                ) {
                    Ok(now) => !cert_to_check.validity().is_valid_at(now),
                    // The clock could not be expressed as an ASN.1 time: assume the worst, so the
                    // certificate is only honoured where expiry is not enforced.
                    Err(_) => true,
                }
            }
        };

        if cert_to_check
            .verify_signature(Some(issuer.public_key()))
            .is_ok()
        {
            for crl_record in self.crl_list.iter() {
                if crl_record.serial == cert_to_check.serial {
                    return None;
                }
            }

            let cert_data = ClientCertificateData {
                cn,
                ca_id: ca_id.to_string(),
                accepted_outside_validity,
            };

            let cert_data = Arc::new(cert_data);

            return Some(cert_data);
        }

        None
    }

    pub fn get_names(&self) -> &[rustls::DistinguishedName] {
        &self.names
    }

    /// CN / expiry of the trust anchor, for the admin surfaces. Unparseable DER is reported as
    /// `Unknown` rather than panicking — the same certificate is rejected at verification time.
    pub fn get_ca_info(&self) -> ClientCertificateCaInfo {
        let Ok((_, cert)) = X509Certificate::from_der(self.ca_content.as_ref()) else {
            return ClientCertificateCaInfo {
                cn: "Unknown".to_string(),
                expires: DateTimeAsMicroseconds::new(0),
                is_ca: false,
            };
        };

        let cn = cert
            .subject()
            .iter_common_name()
            .next()
            .and_then(|cn| cn.as_str().ok())
            .unwrap_or("Unknown")
            .to_string();

        let expires = cert.validity().not_after.to_datetime().unix_timestamp();

        ClientCertificateCaInfo {
            cn,
            // Unix SECONDS: build micros explicitly - DateTimeAsMicroseconds::from(i64) guesses
            // the unit by magnitude and misreads a "no expiry" (year 9999) not_after.
            expires: DateTimeAsMicroseconds::new(expires * 1_000_000),
            is_ca: cert.is_ca(),
        }
    }

    /// Subject DN + public key of the trust anchor. Two certificates with the same pair are the
    /// same authority (a re-issued CA certificate of the same authority keeps both), which is
    /// what an upload has to match to count as a renewal rather than a switch to a different
    /// authority. `None` when the DER can not be parsed.
    fn authority_identity(&self) -> Option<(Vec<u8>, Vec<u8>)> {
        let (_, cert) = X509Certificate::from_der(self.ca_content.as_ref()).ok()?;

        Some((
            cert.subject().as_raw().to_vec(),
            cert.public_key().raw.to_vec(),
        ))
    }

    /// Whether `self` is the same certification authority as `other` — used to tell a renewal of
    /// the loaded CA from a replacement by an unrelated authority (which changes WHICH CLIENTS
    /// the endpoint trusts and therefore has to be asked for explicitly). Unparseable material on
    /// either side answers `false`: it can not be shown to be the same authority.
    pub fn is_same_authority_as(&self, other: &Self) -> bool {
        match (self.authority_identity(), other.authority_identity()) {
            (Some(left), Some(right)) => left == right,
            _ => false,
        }
    }

    /// Common Name of the trust anchor's subject, for messages that have to name it.
    pub fn get_cn(&self) -> String {
        self.get_ca_info().cn
    }

    /// The same CA with a different revocation list. Used by the manual upload, which validates
    /// the certificate material before it knows which CRL it will end up carrying.
    pub fn with_crl(
        &self,
        crl_list: Vec<CrlRecord>,
        crl_file_source: Option<OverSshConnectionSettings>,
    ) -> Self {
        Self {
            ca_content: self.ca_content.clone(),
            names: self.names.clone(),
            ca_file_source: self.ca_file_source.clone(),
            crl_list,
            crl_file_source,
        }
    }

    /// `local_source` for a CA resolved from the configured file source, `manually_provided`
    /// for one uploaded at runtime.
    pub fn origin_as_str(&self) -> &'static str {
        if self.ca_file_source.is_some() {
            "local_source"
        } else {
            "manually_provided"
        }
    }

    pub fn update_crl(&self, crl: Vec<CrlRecord>) -> Self {
        Self {
            ca_content: self.ca_content.clone(),
            names: self.names.clone(),
            ca_file_source: self.ca_file_source.clone(),
            crl_list: crl,
            crl_file_source: self.crl_file_source.clone(),
        }
    }
}
