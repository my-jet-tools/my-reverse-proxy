use std::sync::Arc;

use crate::types::ListenHost;

use super::*;

#[derive(Clone)]
pub struct HttpListenPortConfiguration {
    pub endpoints: Vec<Arc<HttpEndpointInfo>>,
    pub listen_endpoint_type: ListenHttpEndpointType,
    pub listen_host: ListenHost,
}

impl HttpListenPortConfiguration {
    pub fn new(endpoint_info: Arc<HttpEndpointInfo>, listen_host: ListenHost) -> Self {
        Self {
            listen_endpoint_type: endpoint_info.listen_endpoint_type,
            endpoints: vec![endpoint_info],
            listen_host,
        }
    }

    /// Puts the endpoint of a host in place of the one it had, or next to the others. The
    /// endpoints of the names of `additional_hosts` of the one replaced go with it: they are
    /// copies of it, and are put next to the new one anew (`with_additional_hosts`).
    pub fn insert_or_replace_configuration(&mut self, endpoint_info: HttpEndpointInfo) {
        let host_id = endpoint_info.as_str().to_string();

        let index = self
            .endpoints
            .iter()
            .position(|itm| itm.host_endpoint.as_str() == host_id);

        match index {
            Some(index) => {
                self.endpoints[index] = Arc::new(endpoint_info);
                self.endpoints
                    .retain(|itm| itm.additional_host_of.as_deref() != Some(host_id.as_str()));
            }
            None => {
                self.endpoints.push(Arc::new(endpoint_info));
            }
        }
    }

    /// The configuration with `remove` picking which endpoints go - `None` if none is left. The
    /// very same `Arc` if it picks none: the connections of the port have nothing to pick up.
    pub fn without_endpoints(
        config: &Arc<Self>,
        remove: impl Fn(&HttpEndpointInfo) -> bool,
    ) -> Option<Arc<Self>> {
        if !config.endpoints.iter().any(|itm| remove(itm)) {
            return Some(config.clone());
        }

        let endpoints: Vec<_> = config
            .endpoints
            .iter()
            .filter(|itm| !remove(itm))
            .cloned()
            .collect();

        // A port is of the type of its first endpoint: when that one went, of the type of the
        // endpoint which is first now.
        let listen_endpoint_type = endpoints.first()?.listen_endpoint_type;

        Some(Arc::new(Self {
            endpoints,
            listen_endpoint_type,
            listen_host: config.listen_host.clone(),
        }))
    }

    /// The configuration with an endpoint for each of `names` - names of `additional_hosts` on
    /// this port - next to the endpoint of the host it is a name of: a copy of that endpoint
    /// under the name ([`HttpEndpointInfo::new_additional_host`]). Returns the names which can
    /// not be served, each with why.
    pub fn with_additional_hosts<'s>(
        config: &Arc<Self>,
        names: &[AdditionalHostName<'s>],
    ) -> (
        Arc<Self>,
        Vec<(AdditionalHostName<'s>, AdditionalHostRefusal)>,
    ) {
        let mut refused = Vec::new();

        if names.is_empty() {
            return (config.clone(), refused);
        }

        let hosts: std::collections::HashMap<&str, &Arc<HttpEndpointInfo>> = config
            .endpoints
            .iter()
            .filter(|itm| itm.additional_host_of.is_none())
            .map(|itm| (itm.as_str(), itm))
            .collect();

        let mut taken: std::collections::HashSet<String> = config
            .endpoints
            .iter()
            .map(|itm| itm.as_str().to_ascii_lowercase())
            .collect();

        let mut endpoints = config.endpoints.clone();

        for name in names {
            let Some(host) = hosts.get(name.additional_host_of) else {
                refused.push((name.clone(), AdditionalHostRefusal::HostNotServed));
                continue;
            };

            if !taken.insert(name.host_id.to_ascii_lowercase()) {
                refused.push((
                    name.clone(),
                    AdditionalHostRefusal::Other("another host of the port has this name".into()),
                ));
                continue;
            }

            match EndpointHttpHostString::new(name.host_id.to_string()) {
                Ok(host_endpoint) => endpoints.push(Arc::new(
                    host.new_additional_host(host_endpoint, name.dynamic_host),
                )),
                Err(err) => refused.push((name.clone(), AdditionalHostRefusal::Other(err))),
            }
        }

        let result = Arc::new(Self {
            endpoints,
            listen_endpoint_type: config.listen_endpoint_type,
            listen_host: config.listen_host.clone(),
        });

        (result, refused)
    }

    /// The client timeouts of the port before it is known which of its endpoints a connection
    /// is for - during the TLS handshake, and until the first request names its host: the
    /// longest of each among the endpoints, so none of them is held to less than its own.
    pub fn client_timeouts(&self) -> crate::types::ClientTimeouts {
        let mut endpoints = self.endpoints.iter();

        let Some(first) = endpoints.next() else {
            return crate::types::ClientTimeouts::default();
        };

        endpoints.fold(first.client_timeouts, |result, endpoint_info| {
            result.longest(&endpoint_info.client_timeouts)
        })
    }

    /// The endpoint a request for `server_name` is served by: the one with this very name - of a
    /// host, or of a name of its `additional_hosts` - and, if none has it, the endpoint without a
    /// name, which serves whatever no other endpoint of the port is named for. `None` for
    /// `server_name` - there is no name to choose by: the endpoint without a name as well.
    pub fn get_http_endpoint_info(
        &self,
        server_name: Option<&str>,
    ) -> Option<Arc<HttpEndpointInfo>> {
        server_name
            .and_then(|server_name| self.find_named_endpoint(server_name))
            .or_else(|| self.find_endpoint_without_name())
            .cloned()
    }

    fn find_named_endpoint(&self, server_name: &str) -> Option<&Arc<HttpEndpointInfo>> {
        self.endpoints
            .iter()
            .find(|itm| match itm.host_endpoint.get_server_name() {
                Some(name) => name.eq_ignore_ascii_case(server_name),
                None => false,
            })
    }

    fn find_endpoint_without_name(&self) -> Option<&Arc<HttpEndpointInfo>> {
        self.endpoints
            .iter()
            .find(|itm| !itm.host_endpoint.has_server_name())
    }

    /*
       pub fn get_listen_endpoint_type(&self) -> ListenHttpEndpointType {
           self.endpoint_info[0].listen_endpoint_type
       }
    */
    /// The certificate of the endpoint `server_name` is served by - picked as
    /// [`Self::get_http_endpoint_info`] picks it.
    pub fn get_ssl_certificate<'s>(
        &'s self,
        server_name: &str,
    ) -> Option<(SslCertificateIdRef<'s>, Arc<HttpEndpointInfo>)> {
        let endpoint_info = self
            .find_named_endpoint(server_name)
            .or_else(|| self.find_endpoint_without_name())?;

        let ssl_id = endpoint_info.ssl_certificate_id.as_ref()?;

        Some((ssl_id.into(), endpoint_info.clone()))
    }
    /*
    pub fn get_ssl_certificates(&self) -> Option<Vec<&SslCertificateId>> {
        let mut result: Vec<&SslCertificateId> = vec![];

        for endpoint_info in &self.endpoint_info {
            if let Some(ssl_id) = endpoint_info.ssl_certificate_id.as_ref() {
                if !result.iter().any(|itm| itm.as_str() == ssl_id.as_str()) {
                    result.push(ssl_id);
                }
            }
        }

        if result.len() > 0 {
            return Some(result);
        }

        None
    }
     */
}

/// A name of `additional_hosts` to be served on a port: see
/// [`HttpListenPortConfiguration::with_additional_hosts`].
#[derive(Clone, Debug)]
pub struct AdditionalHostName<'s> {
    /// The name on the port of its host: `www.example.com:443`.
    pub host_id: &'s str,
    /// The id of the host it is a name of.
    pub additional_host_of: &'s str,
    /// The name came from `dynamic_hosts.url`.
    pub dynamic_host: bool,
}

/// Why a name of `additional_hosts` is not served.
#[derive(Debug)]
pub enum AdditionalHostRefusal {
    /// The host it is a name of is not served on the port: it did not compile, or was refused.
    HostNotServed,
    Other(String),
}

impl AdditionalHostRefusal {
    pub fn describe(&self, additional_host_of: &str) -> String {
        match self {
            AdditionalHostRefusal::HostNotServed => {
                format!("'{additional_host_of}', whose name it is, is not served")
            }
            AdditionalHostRefusal::Other(err) => err.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::settings::HostSettings;
    use crate::settings_compiled::SettingsCompiled;

    async fn port_of(hosts: &[&str]) -> Arc<HttpListenPortConfiguration> {
        let settings = SettingsCompiled::default();
        let mut result = None;

        for host_id in hosts {
            let host_settings: HostSettings = my_settings_reader::serde_yaml::from_str(
                "endpoint:\n  type: http\nlocations:\n- proxy_pass_to: http://127.0.0.1:9000\n",
            )
            .unwrap();

            result = Some(
                crate::scripts::compile_host_configuration(
                    &settings,
                    EndpointHttpHostString::new(host_id.to_string()).unwrap(),
                    &host_settings,
                    result,
                )
                .await
                .unwrap(),
            );
        }

        match result.unwrap() {
            ListenConfiguration::Http(config) => config,
            _ => panic!("not an http port"),
        }
    }

    fn name<'s>(host_id: &'s str, additional_host_of: &'s str) -> AdditionalHostName<'s> {
        AdditionalHostName {
            host_id,
            additional_host_of,
            dynamic_host: false,
        }
    }

    fn served_by(config: &HttpListenPortConfiguration, server_name: Option<&str>) -> String {
        config
            .get_http_endpoint_info(server_name)
            .map(|itm| itm.as_str().to_string())
            .unwrap_or_default()
    }

    /// A name is served by a copy of the endpoint of its host: the same locations - and so the
    /// same upstream connections - under a name of its own.
    #[tokio::test]
    async fn a_name_is_served_by_the_endpoint_of_its_host_under_its_own_name() {
        let config = port_of(&["a.localhost:7200", "b.localhost:7200"]).await;

        let (config, refused) = HttpListenPortConfiguration::with_additional_hosts(
            &config,
            &[
                name("www.a.localhost:7200", "a.localhost:7200"),
                name("WWW.A.localhost:7200", "a.localhost:7200"),
                name("B.localhost:7200", "a.localhost:7200"),
                name("c.localhost:7200", "missing.localhost:7200"),
            ],
        );

        let refused: Vec<_> = refused.iter().map(|(itm, _)| itm.host_id).collect();
        assert_eq!(
            refused,
            [
                "WWW.A.localhost:7200",
                "B.localhost:7200",
                "c.localhost:7200"
            ]
        );

        let host = config.get_http_endpoint_info(Some("a.localhost")).unwrap();
        let name = config
            .get_http_endpoint_info(Some("WWW.a.localhost"))
            .unwrap();

        assert_eq!(name.as_str(), "www.a.localhost:7200");
        assert_eq!(name.additional_host_of.as_deref(), Some("a.localhost:7200"));
        assert!(host.additional_host_of.is_none());
        assert_eq!(name.locations.len(), host.locations.len());
        for (name_location, host_location) in name.locations.iter().zip(host.locations.iter()) {
            assert!(Arc::ptr_eq(name_location, host_location));
        }
        assert_eq!(served_by(&config, Some("b.localhost")), "b.localhost:7200");
    }

    /// The names of a host go with its endpoint when it is replaced: they are copies of it, and
    /// are put next to the new endpoint anew.
    #[tokio::test]
    async fn the_names_of_a_host_go_with_it() {
        let config = port_of(&["a.localhost:7201", "b.localhost:7201"]).await;
        let (config, _) = HttpListenPortConfiguration::with_additional_hosts(
            &config,
            &[
                name("www.a.localhost:7201", "a.localhost:7201"),
                name("www.b.localhost:7201", "b.localhost:7201"),
            ],
        );

        let mut replaced = config.as_ref().clone();
        let new_a = config.endpoints[0].as_ref().clone();
        replaced.insert_or_replace_configuration(new_a);
        let ids: Vec<_> = replaced.endpoints.iter().map(|itm| itm.as_str()).collect();
        assert_eq!(
            ids,
            [
                "a.localhost:7201",
                "b.localhost:7201",
                "www.b.localhost:7201"
            ]
        );
    }

    /// The endpoint with the very name serves a request; the one without a name serves what no
    /// other endpoint is named for - whatever order they were put on the port in.
    #[tokio::test]
    async fn the_endpoint_without_a_name_serves_what_no_other_is_named_for() {
        for hosts in [["7202", "a.localhost:7202"], ["a.localhost:7202", "7202"]] {
            let config = port_of(&hosts).await;
            let (config, _) = HttpListenPortConfiguration::with_additional_hosts(
                &config,
                &[name("www.a.localhost:7202", "a.localhost:7202")],
            );

            assert_eq!(served_by(&config, Some("A.localhost")), "a.localhost:7202");
            assert_eq!(
                served_by(&config, Some("www.a.localhost")),
                "www.a.localhost:7202"
            );
            assert_eq!(served_by(&config, Some("other.localhost")), "7202");
            assert_eq!(served_by(&config, None), "7202");
        }

        let config = port_of(&["a.localhost:7203", "b.localhost:7203"]).await;
        assert_eq!(served_by(&config, Some("other.localhost")), "");
        assert_eq!(served_by(&config, None), "");
    }

    /// Nothing to take away: the very same configuration, which the connections of the port
    /// have nothing to pick up from.
    #[tokio::test]
    async fn a_configuration_nothing_is_taken_from_is_the_same() {
        let config = port_of(&["a.localhost:7204", "b.localhost:7204"]).await;

        let same = HttpListenPortConfiguration::without_endpoints(&config, |_| false).unwrap();
        assert!(Arc::ptr_eq(&same, &config));

        let fewer = HttpListenPortConfiguration::without_endpoints(&config, |itm| {
            itm.as_str() == "a.localhost:7204"
        })
        .unwrap();
        assert_eq!(fewer.endpoints.len(), 1);

        assert!(HttpListenPortConfiguration::without_endpoints(&config, |_| true).is_none());
    }
}
