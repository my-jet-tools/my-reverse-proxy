use crate::self_signed_cert::SELF_SIGNED_CERT_NAME;

#[derive(Debug, Clone)]
pub struct SslCertificateId(String);

impl SslCertificateId {
    pub fn new(cert_id: String) -> Self {
        Self(cert_id)
    }

    pub fn new_as_self_signed() -> Self {
        Self(SELF_SIGNED_CERT_NAME.to_string())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn as_ref<'s>(&'s self) -> SslCertificateIdRef<'s> {
        SslCertificateIdRef::new(&self.0)
    }

    pub fn is_self_signed(&self) -> bool {
        self.0 == SELF_SIGNED_CERT_NAME
    }
}

impl From<String> for SslCertificateId {
    fn from(val: String) -> Self {
        SslCertificateId::new(val)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct SslCertificateIdRef<'s>(&'s str);

impl<'s> SslCertificateIdRef<'s> {
    pub fn new(cert_id: &'s str) -> Self {
        Self(cert_id)
    }

    pub fn as_str(&'s self) -> &'s str {
        self.0
    }

    pub fn is_self_signed(&self) -> bool {
        self.0 == SELF_SIGNED_CERT_NAME
    }
}

impl std::fmt::Display for SslCertificateIdRef<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}

impl From<SslCertificateIdRef<'_>> for SslCertificateId {
    fn from(val: SslCertificateIdRef<'_>) -> Self {
        SslCertificateId::new(val.0.to_string())
    }
}

impl<'s> From<&'s SslCertificateId> for SslCertificateIdRef<'s> {
    fn from(val: &'s SslCertificateId) -> Self {
        SslCertificateIdRef::new(val.as_str())
    }
}
