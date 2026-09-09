use my_tls::crl::CrlRecord;
use rust_extensions::date_time::DateTimeAsMicroseconds;

/// Reads the revoked serials out of a certificate revocation list in PEM format.
///
/// Used for every CRL this process reads — the operator-pasted one and the one behind a
/// configured `revocation_list:` source — so both paths yield the same revocation set.
/// `my_tls::crl::read` is not used: it unwraps its way through both the PEM and the DER (a
/// malformed file panics the caller) and it only ever looks at the FIRST block of the file,
/// which would silently ignore the rest of a multi-block CRL bundle.
pub fn parse_crl_pem(src: &[u8]) -> Result<Vec<CrlRecord>, String> {
    use x509_parser::prelude::FromDer;

    let mut reader = std::io::BufReader::new(src);

    let mut result = Vec::new();
    let mut found = false;

    for crl_der in rustls_pemfile::crls(&mut reader) {
        let crl_der = crl_der.map_err(|err| format!("Error reading the CRL PEM: {}", err))?;

        let (_, list) =
            x509_parser::revocation_list::CertificateRevocationList::from_der(crl_der.as_ref())
                .map_err(|err| format!("The provided CRL is not a valid X509 CRL: {}", err))?;

        found = true;

        for revoked in list.iter_revoked_certificates() {
            result.push(CrlRecord {
                serial: revoked.serial().clone(),
                // Unix SECONDS - built explicitly, DateTimeAsMicroseconds::from(i64) guesses
                // the unit by magnitude.
                revoked: DateTimeAsMicroseconds::new(
                    revoked.revocation_date.timestamp() * 1_000_000,
                ),
            });
        }
    }

    if !found {
        return Err(
            "No '-----BEGIN X509 CRL-----' block found in the provided revocation list".to_string(),
        );
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::parse_crl_pem;

    #[test]
    fn reads_a_well_formed_crl() {
        // `my_tls` ships a real (empty) CRL - good enough to prove the PEM+DER path works.
        let records = parse_crl_pem(my_tls::crl::EMPTY_CRL.as_bytes()).unwrap();
        assert!(records.is_empty());
    }

    #[test]
    fn broken_material_is_an_error_not_a_panic() {
        // This is the whole point of not calling `my_tls::crl::read` on operator input.
        assert!(
            parse_crl_pem(b"-----BEGIN X509 CRL-----\nnot base64\n-----END X509 CRL-----").is_err()
        );
        assert!(parse_crl_pem(b"").is_err());
        assert!(parse_crl_pem(b"nothing here at all").is_err());
    }

    #[test]
    fn a_certificate_is_not_a_revocation_list() {
        let not_a_crl = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----";
        assert!(parse_crl_pem(not_a_crl.as_bytes()).is_err());
    }
}
