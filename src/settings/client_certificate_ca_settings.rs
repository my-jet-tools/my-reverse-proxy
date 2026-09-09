use serde::*;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ClientCertificateCaSettings {
    pub id: String,
    /// Source of the CA certificate (local file or over-ssh). When omitted (or empty), the CA
    /// is "manual" — it is not resolved from a source on startup and must be pushed at runtime:
    /// from the admin ui (the "Client cert CA not loaded" badge on the endpoint) or via
    /// POST /api/ClientCertificates/Init(FromPem). Until it arrives every TLS handshake to the
    /// endpoints requiring it is cut, so nothing is ever served unverified.
    pub ca: Option<String>,
    pub revocation_list: Option<String>,
    /// When true, client certificates verified against this ca are accepted regardless of their
    /// validity dates. It is the deliberate escape hatch for a partner whose certificates are
    /// expired but who still has to connect - off by default, and reported on every admin
    /// surface so it can not be forgotten.
    pub unlimited_expiration: Option<bool>,
}

impl ClientCertificateCaSettings {
    pub fn get_unlimited_expiration(&self) -> bool {
        self.unlimited_expiration.unwrap_or(false)
    }

    /// `None` means the CA has no configured source and is uploaded at runtime.
    ///
    /// A revocation list without a CA source is refused: the CRL of a manually uploaded CA
    /// travels with the upload (or is carried over from the CA it replaces), so a `revocation_list`
    /// here would never be read and would quietly look like revocation was in place.
    pub fn get_source(&self) -> Result<Option<&str>, String> {
        let ca = self.ca.as_deref().filter(|s| !s.trim().is_empty());

        if ca.is_none() {
            if self
                .revocation_list
                .as_deref()
                .filter(|s| !s.trim().is_empty())
                .is_some()
            {
                return Err(format!(
                    "Client certificate ca '{}' has a 'revocation_list' but no 'ca' source. Specify 'ca', or neither (manual upload from the admin ui / POST /api/ClientCertificates/Init) - a revocation list alone is never applied.",
                    self.id
                ));
            }

            return Ok(None);
        }

        Ok(ca)
    }
}
