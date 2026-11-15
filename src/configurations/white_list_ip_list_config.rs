use std::{
    collections::{BTreeMap, HashMap},
    sync::Arc,
};

use crate::types::{IntoIp, WhiteListedIpList};

pub struct WhiteListedIpListConfigurations {
    data: HashMap<String, Arc<WhiteListedIpList>>,
}

impl WhiteListedIpListConfigurations {
    pub fn new() -> Self {
        Self {
            data: HashMap::new(),
        }
    }

    pub fn insert_or_update(&mut self, id: String, white_list_ip: WhiteListedIpList) {
        self.data.insert(id, Arc::new(white_list_ip));
    }

    /// The list is not declared any more: what it held before must not go on letting anybody in.
    pub fn remove(&mut self, id: &str) {
        self.data.remove(id);
    }

    /// A list which is not here - not declared in the settings - lets nobody in.
    pub fn is_white_listed(&self, id: &str, ip: &impl IntoIp) -> bool {
        if let Some(white_list) = self.data.get(id) {
            return white_list.is_whitelisted(ip);
        }

        false
    }

    pub fn get_all<TResult>(
        &self,
        convert_value: impl Fn(&WhiteListedIpList) -> TResult,
    ) -> BTreeMap<String, TResult> {
        let mut result = BTreeMap::new();

        for (key, value) in &self.data {
            result.insert(key.clone(), convert_value(value));
        }

        result
    }
}
