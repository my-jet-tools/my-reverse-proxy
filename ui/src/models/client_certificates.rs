use serde::{Deserialize, Serialize};

/// Body of `POST /api/ClientCertificates/InitFromPem`. The names must match the
/// `#[http_body(name = ...)]` names declared by `InitClientCertificateCaFromPemHttpInput`
/// in `my-reverse-proxy`. `ca` and `crl` carry base64 of the PEM text — json would
/// otherwise have to escape every line break of the pasted material.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct InitClientCaRequestModel {
    pub ca_id: String,
    pub ca: String,
    pub crl: Option<String>,
}

/// Mirror of `InitClientCertificateCaResultHttpModel` — what the proxy reports about the
/// client-certificate CA it has just installed.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct InitClientCaResultModel {
    pub ca_id: String,
    pub cn: String,
    pub expires: String,
    pub is_ca: bool,
    pub endpoints: Vec<String>,
    pub crl_records: usize,
    pub crl_kept_from_previous: bool,
}
