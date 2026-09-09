use std::{collections::HashMap, sync::Arc};

use my_ssh::ssh_settings::OverSshConnectionSettings;
use my_tls::crl::CrlRecord;

use crate::tcp_listener::https::ClientCertificateCa;

use crate::configurations::*;

pub struct ClientCertificatesCache {
    data: HashMap<String, Arc<ClientCertificateCa>>,
}

impl ClientCertificatesCache {
    pub fn new() -> Self {
        Self {
            data: HashMap::new(),
        }
    }

    pub fn insert(&mut self, cert_id: SslCertificateIdRef, value: Arc<ClientCertificateCa>) {
        self.data.insert(cert_id.to_string(), value);
    }

    pub fn has_certificate(&self, cert_id: SslCertificateIdRef) -> bool {
        return self.data.contains_key(cert_id.as_str());
    }

    pub fn get(&self, cert_id: SslCertificateIdRef) -> Option<Arc<ClientCertificateCa>> {
        return self.data.get(cert_id.as_str()).cloned();
    }

    /// Ids of every client CA currently loaded - used to tell which endpoints reference a CA
    /// that has not arrived yet.
    pub fn get_ids(&self) -> Vec<String> {
        self.data.keys().cloned().collect()
    }

    /// Drops the CA loaded under this id. The endpoints requiring it go back to cutting every
    /// TLS connection (fail-closed) until a CA is provided again - which is what makes this a
    /// usable undo for a wrong upload.
    pub fn remove(&mut self, cert_id: SslCertificateIdRef) -> bool {
        self.data.remove(cert_id.as_str()).is_some()
    }

    pub fn get_list_of_crl(&self) -> Vec<(String, OverSshConnectionSettings)> {
        let mut result = Vec::new();

        for itm in self.data.iter() {
            if itm.1.crl_file_source.is_some() {
                result.push((
                    itm.0.to_string(),
                    itm.1.crl_file_source.as_ref().unwrap().clone(),
                ));
            }
        }

        result
    }

    pub fn update_crl(&mut self, id: String, crl: Vec<CrlRecord>) {
        let data = self.data.remove(&id);

        if data.is_none() {
            return;
        }

        let data = data.unwrap();

        self.data
            .insert(id, Arc::new(data.as_ref().update_crl(crl)));
    }
}
