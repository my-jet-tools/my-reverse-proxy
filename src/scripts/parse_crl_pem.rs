use my_tls::crl::CrlRecord;
use rust_extensions::date_time::DateTimeAsMicroseconds;
use x509_parser::num_bigint::BigUint;

/// The revoked serials of a revocation list, in either of the two forms it comes in:
///
/// - an X.509 CRL in PEM (`-----BEGIN X509 CRL-----`), the way a CA tool writes it -
///   [`parse_crl_pem`];
/// - a YAML array of serials - `- 5`, `[]` when none is revoked - the way ca-api's
///   `GET /api/revoked/v1/list` answers. A serial is a decimal integer; one too big for a YAML
///   integer may come as a string of decimal digits.
///
/// Used for every revocation list this process reads - the one an operator uploads and the one
/// behind a configured `revocation_list:` source - so both paths yield the same revocation set.
pub fn parse_revocation_list(src: &[u8]) -> Result<Vec<CrlRecord>, String> {
    if src
        .windows(PEM_BEGIN.len())
        .any(|window| window == PEM_BEGIN)
    {
        return parse_crl_pem(src);
    }

    parse_revoked_serials(src)
}

const PEM_BEGIN: &[u8] = b"-----BEGIN";

/// A YAML array of revoked serials. A YAML list carries no dates: the moment it is read stands in
/// for them - nothing reads the date, a certificate is refused by its serial alone.
fn parse_revoked_serials(src: &[u8]) -> Result<Vec<CrlRecord>, String> {
    let not_a_list = |why: &str| {
        format!(
            "The revocation list is neither an X.509 CRL in PEM nor a YAML array of serials: {why}"
        )
    };

    if src.iter().all(|byte| byte.is_ascii_whitespace()) {
        return Err(not_a_list("it is empty"));
    }

    let items: Vec<serde_yaml::Value> =
        serde_yaml::from_slice(src).map_err(|err| not_a_list(&err.to_string()))?;

    let read_at = DateTimeAsMicroseconds::now();

    items
        .iter()
        .enumerate()
        .map(|(index, item)| {
            let serial = match item {
                serde_yaml::Value::Number(number) => number.as_u64().map(BigUint::from),
                serde_yaml::Value::String(text)
                    if !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit()) =>
                {
                    BigUint::parse_bytes(text.as_bytes(), 10)
                }
                _ => None,
            };

            let serial = serial.ok_or_else(|| {
                format!(
                    "The revocation list: item #{} is not a serial - a non-negative decimal integer",
                    index + 1
                )
            })?;

            Ok(CrlRecord {
                serial,
                revoked: read_at,
            })
        })
        .collect()
}

/// Reads the revoked serials out of a certificate revocation list in PEM format.
///
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
    use super::{parse_crl_pem, parse_revocation_list};
    use x509_parser::num_bigint::BigUint;

    fn serials(src: &str) -> Vec<BigUint> {
        parse_revocation_list(src.as_bytes())
            .unwrap_or_else(|err| panic!("{src:?}: {err}"))
            .into_iter()
            .map(|record| record.serial)
            .collect()
    }

    /// What ca-api's `/api/revoked/v1/list` answers: serde_yaml of a `Vec<u64>`.
    #[test]
    fn a_yaml_array_of_serials_is_a_revocation_list() {
        assert_eq!(
            serials("- 5\n- 6\n"),
            [BigUint::from(5u64), BigUint::from(6u64)]
        );
        assert_eq!(
            serials("[5, 18446744073709551615]"),
            [BigUint::from(5u64), BigUint::from(u64::MAX)]
        );
        assert!(serials("[]\n").is_empty());

        // Beyond a YAML integer: a string of digits.
        assert_eq!(
            serials("- '340282366920938463463374607431768211456'\n"),
            [BigUint::parse_bytes(b"340282366920938463463374607431768211456", 10).unwrap()]
        );
    }

    #[test]
    fn a_yaml_which_is_not_an_array_of_serials_is_an_error() {
        for src in [
            "",
            "  \n",
            "- -1\n",
            "- 1.5\n",
            "- abc\n",
            "- ''\n",
            "- '0x1f'\n",
            "- [1]\n",
            "hosts: {}\n",
            "5\n",
        ] {
            assert!(parse_revocation_list(src.as_bytes()).is_err(), "{src:?}");
        }
    }

    /// A CRL in PEM is read the way it always was.
    #[test]
    fn a_crl_in_pem_is_still_a_revocation_list() {
        let records = parse_revocation_list(my_tls::crl::EMPTY_CRL.as_bytes()).unwrap();
        assert!(records.is_empty());

        assert!(parse_revocation_list(
            b"-----BEGIN X509 CRL-----\nnot base64\n-----END X509 CRL-----"
        )
        .is_err());
    }

    /// The serials of the list refuse the client certificates with them, and only those - the way
    /// ca-api numbers the certificates it issues (`SerialNumber::from(u64)`).
    #[test]
    fn a_client_certificate_whose_serial_is_listed_is_refused() {
        use rcgen::{
            BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer,
            KeyPair, KeyUsagePurpose, SerialNumber,
        };

        let ca_key = KeyPair::generate().unwrap();
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "revocation test ca");
        ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();
        let issuer = Issuer::new(ca_params, ca_key);

        let client_key = KeyPair::generate().unwrap();
        let mut client_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        client_params
            .distinguished_name
            .push(DnType::CommonName, "partner");
        client_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        client_params.serial_number = Some(SerialNumber::from(5u64));
        let client_cert = client_params.signed_by(&client_key, &issuer).unwrap();

        let verify = |list: &str| {
            let ca = crate::tcp_listener::https::ClientCertificateCa::new(
                vec![ca_cert.der().clone()],
                None,
                parse_revocation_list(list.as_bytes()).unwrap(),
                None,
            )
            .unwrap();

            ca.verify_cert(client_cert.der(), "revocation-test", None)
                .is_some()
        };

        assert!(verify("[]\n"), "nothing is revoked");
        assert!(verify("- 6\n- 7\n"), "another serial is revoked");
        assert!(!verify("- 6\n- 5\n"), "serial 5 is revoked");
    }

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
