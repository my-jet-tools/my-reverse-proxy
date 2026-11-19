use crate::settings::*;

use super::{SettingsCompiled, VariablesCompiled};

impl SettingsCompiled {
    /// The settings files, and what the urls of `real_time_configurations` answered last - their
    /// hosts next to the hosts of the files, their keys with the keys of the files.
    pub async fn load_settings() -> Result<Self, String> {
        let mut result = Self::default();

        let settings_model = crate::settings::SettingsModel::load_async(None).await?;
        let include_settings = load_includes(&settings_model).await?;
        result.populate(settings_model, include_settings)?;

        // Only what the urls the settings name now gave: a url taken out of the list gives
        // nothing any more, and one put into it gives nothing until it is read.
        if let Some(real_time_configurations) = result.real_time_configurations.as_ref() {
            let answers = crate::app::APP_CTX
                .real_time_configurations
                .get_answers(&real_time_configurations.urls);

            if !answers.is_empty() {
                result.set_real_time_answers(&answers);
            }
        }

        Ok(result)
    }

    pub fn load_settings_block() -> Result<Self, String> {
        let mut result = Self::default();

        let settings_model = crate::settings::SettingsModel::load(None)?;
        let include_settings = load_includes_block(&settings_model)?;
        result.populate(settings_model, include_settings)?;

        Ok(result)
    }

    fn populate(
        &mut self,
        mut settings_model: SettingsModel,
        mut include_settings: Vec<SettingsModel>,
    ) -> Result<(), String> {
        let mut variables = VariablesCompiled::default();
        variables.merge(&mut settings_model);

        for sub_settings in include_settings.iter_mut() {
            variables.merge(sub_settings);
        }

        self.populate_hosts(&mut settings_model, &variables)?;
        self.populate_ssh_configs(&mut settings_model, &variables)?;
        self.populate_ssl_certificates(&mut settings_model, &variables)?;
        self.populate_ca_certificates(&mut settings_model, &variables)?;
        self.populate_global_settings(&mut settings_model, &variables)?;
        self.populate_g_auth(&mut settings_model, &variables)?;
        self.populate_oauth(&mut settings_model, &variables)?;
        self.populate_endpoint_templates(&mut settings_model, &variables)?;
        self.populate_allowed_users(&mut settings_model, &variables)?;
        self.populate_ip_white_lists(&mut settings_model, &variables)?;
        self.populate_country_white_lists(&mut settings_model, &variables)?;
        self.populate_gateway_server(&mut settings_model, &variables)?;
        self.populate_gateway_client(&mut settings_model, &variables)?;
        self.populate_real_time_configurations(&mut settings_model, &variables)?;
        self.populate_api_keys(&mut settings_model, &variables)?;

        for sub_settings in include_settings.iter_mut() {
            self.populate_hosts(sub_settings, &variables)?;
            self.populate_ssh_configs(sub_settings, &variables)?;
            self.populate_ssl_certificates(sub_settings, &variables)?;
            self.populate_ca_certificates(sub_settings, &variables)?;
            self.populate_global_settings(sub_settings, &variables)?;
            self.populate_g_auth(sub_settings, &variables)?;
            self.populate_oauth(sub_settings, &variables)?;
            self.populate_endpoint_templates(sub_settings, &variables)?;
            self.populate_allowed_users(sub_settings, &variables)?;
            self.populate_ip_white_lists(sub_settings, &variables)?;
            self.populate_country_white_lists(sub_settings, &variables)?;
            self.populate_gateway_server(sub_settings, &variables)?;
            self.populate_gateway_client(sub_settings, &variables)?;
            self.populate_real_time_configurations(sub_settings, &variables)?;
            self.populate_api_keys(sub_settings, &variables)?;
        }

        self.variables = variables;

        // Once every file is read: a host written again in a later file replaces the one before,
        // and its `additional_hosts` with it - then the names are put together, none of them
        // depending on the order the files were read in.
        self.resolve_additional_hosts_of_files();

        Ok(())
    }

    fn populate_real_time_configurations(
        &mut self,
        settings_model: &mut SettingsModel,
        variables: &VariablesCompiled,
    ) -> Result<(), String> {
        if settings_model.dynamic_hosts.take().is_some() {
            return Err(
                "dynamic_hosts is renamed: it is real_time_configurations now, with a list of urls - 'urls:' in place of 'url:'"
                    .to_string(),
            );
        }

        let Some(itm) = settings_model.real_time_configurations.take() else {
            return Ok(());
        };

        // One list: a second one would quietly replace the first, depending on the order the
        // files are read in.
        if self.real_time_configurations.is_some() {
            return Err(
                "real_time_configurations is declared more than once. It can be declared in one settings file only."
                    .to_string(),
            );
        }

        let mut urls = Vec::with_capacity(itm.urls.len());
        for url in itm.urls {
            urls.push(variables.apply_variables(url)?);
        }

        let itm = RealTimeConfigurationsSettings {
            urls,
            refresh_interval: itm.refresh_interval,
            request_timeout: itm.request_timeout,
        };

        itm.check()?;

        self.real_time_configurations = Some(itm);

        Ok(())
    }

    /// The keys of `api_keys:` of a settings file: added to the sets of the same ids the other
    /// files declare.
    fn populate_api_keys(
        &mut self,
        settings_model: &mut SettingsModel,
        variables: &VariablesCompiled,
    ) -> Result<(), String> {
        let Some(api_keys) = settings_model.api_keys.take() else {
            return Ok(());
        };

        for (id, keys) in api_keys {
            let id = variables.apply_variables(id)?;
            let keys = keys
                .into_iter()
                .map(|key| variables.apply_variables_protected(key))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|err| format!("api_keys '{id}': {err}"))?;
            let keys = crate::api_keys::check_api_keys(&id, keys)?;

            crate::api_keys::merge_api_keys(
                &mut self.api_keys,
                &std::collections::HashMap::from([(id, keys)]),
            );
        }

        Ok(())
    }

    fn populate_ssh_configs(
        &mut self,
        settings_model: &mut SettingsModel,
        variables: &VariablesCompiled,
    ) -> Result<(), String> {
        if let Some(ssh) = settings_model.ssh.take() {
            for (ssh_id, ssh_settings) in ssh {
                let ssh_settings = SshConfigSettings {
                    password: variables.apply_variables_protected_opt(ssh_settings.password)?,
                    private_key_file: variables
                        .apply_variables_opt(ssh_settings.private_key_file)?,
                    passphrase: variables.apply_variables_protected_opt(ssh_settings.passphrase)?,
                };

                self.ssh.insert(ssh_id, ssh_settings);
            }
        }

        Ok(())
    }

    fn populate_hosts(
        &mut self,
        settings_model: &mut SettingsModel,
        variables: &VariablesCompiled,
    ) -> Result<(), String> {
        let hosts = std::mem::take(&mut settings_model.hosts);
        for (host_id, host_settings) in hosts {
            let (host_id, host_settings) = compile_host(host_id, host_settings, variables)?;

            // A host written again replaces the one before, as it always has - and the
            // `additional_hosts` of that one go with it.
            self.hosts.insert(host_id, host_settings);
        }

        Ok(())
    }

    fn populate_ssl_certificates(
        &mut self,
        settings_model: &mut SettingsModel,
        variables: &VariablesCompiled,
    ) -> Result<(), String> {
        if let Some(ssl) = settings_model.ssl_certificates.take() {
            for itm in ssl {
                let itm = SslCertificatesSettingsModel {
                    id: variables.apply_variables(itm.id)?,
                    certificate: variables.apply_variables_opt(itm.certificate)?,
                    private_key: variables.apply_variables_opt(itm.private_key)?,
                };

                // Same reason as for the client certificate ca list: the first match wins, so a
                // duplicate id quietly shadows the other entry.
                if self
                    .ssl_certificates
                    .iter()
                    .any(|existing| existing.id == itm.id)
                {
                    return Err(format!(
                        "SSL certificate id '{}' is declared more than once. Ids must be unique - the duplicate would be ignored.",
                        itm.id
                    ));
                }

                self.ssl_certificates.push(itm);
            }
        }

        Ok(())
    }

    fn populate_ca_certificates(
        &mut self,
        settings_model: &mut SettingsModel,
        variables: &VariablesCompiled,
    ) -> Result<(), String> {
        if let Some(ca_certs) = settings_model.client_certificate_ca.take() {
            for itm in ca_certs {
                let itm = ClientCertificateCaSettings {
                    id: variables.apply_variables(itm.id)?,
                    ca: variables.apply_variables_opt(itm.ca)?,
                    revocation_list: variables.apply_variables_opt(itm.revocation_list)?,
                    unlimited_expiration: itm.unlimited_expiration,
                };

                // Structural validation belongs here: a per-endpoint failure to RESOLVE a ca is
                // deliberately non-fatal (the endpoint keeps listening so the ca can be uploaded),
                // and it would otherwise swallow an entry that can never work at all.
                itm.get_source()?;

                // Lookups take the first match, so a duplicate id silently shadows the other
                // entry - and with `ca:` optional the shadowed one may be the only one with a
                // source.
                if self
                    .client_certificate_ca
                    .iter()
                    .any(|existing| existing.id == itm.id)
                {
                    return Err(format!(
                        "Client certificate ca id '{}' is declared more than once. Ids must be unique - the duplicate would be ignored.",
                        itm.id
                    ));
                }

                self.client_certificate_ca.push(itm);
            }
        }

        Ok(())
    }

    fn populate_global_settings(
        &mut self,
        settings_model: &mut SettingsModel,
        variables: &VariablesCompiled,
    ) -> Result<(), String> {
        if let Some(itm) = settings_model.global_settings.take() {
            itm.get_debug_ip()?;
            itm.get_http_control_addr()?;

            for entry in itm.ip_blocklist_white_list.iter().flatten() {
                crate::types::check_ip_white_list_entry(entry)
                    .map_err(|err| format!("global_settings.ip_blocklist_white_list: {err}"))?;
            }

            let global_settings = GlobalSettings {
                connection_settings: itm.connection_settings,
                all_http_endpoints: if let Some(itm) = itm.all_http_endpoints {
                    Some(AllHttpEndpointsGlobalSettings {
                        modify_http_headers: super::populate_modify_http_headers_settings(
                            itm.modify_http_headers,
                            variables,
                        )?,
                    })
                } else {
                    None
                },
                show_error_description_on_error_page: itm.show_error_description_on_error_page,
                http_control_port: itm.http_control_port,
                http_control_ip: itm.http_control_ip,
                control_unix_socket: variables.apply_variables_opt(itm.control_unix_socket)?,
                default_h2_livness_url: itm.default_h2_livness_url,
                ip_blocklist_white_list: itm.ip_blocklist_white_list,
                debug_ip: itm.debug_ip,
                pool_supervisor_interval: itm.pool_supervisor_interval,
                secure_store_file: variables.apply_variables_opt(itm.secure_store_file)?,
                timeouts: itm.timeouts,
            };

            global_settings.get_control_unix_socket()?;

            self.global_settings = Some(global_settings);
        }

        Ok(())
    }

    fn populate_g_auth(
        &mut self,
        settings_model: &mut SettingsModel,
        variables: &VariablesCompiled,
    ) -> Result<(), String> {
        if let Some(g_auth) = settings_model.g_auth.take() {
            for (key, itm) in g_auth {
                self.g_auth.insert(
                    variables.apply_variables(key)?,
                    GoogleAuthSettings {
                        client_id: variables.apply_variables(itm.client_id)?,
                        client_secret: variables.apply_variables_protected(itm.client_secret)?,
                        whitelisted_domains: variables.apply_variables(itm.whitelisted_domains)?,
                    },
                );
            }
        }

        Ok(())
    }

    fn populate_oauth(
        &mut self,
        settings_model: &mut SettingsModel,
        variables: &VariablesCompiled,
    ) -> Result<(), String> {
        if let Some(oauth) = settings_model.oauth.take() {
            for (key, itm) in oauth {
                self.oauth.insert(
                    variables.apply_variables(key)?,
                    OAuthSettings {
                        client_id: variables.apply_variables(itm.client_id)?,
                        client_secret: variables.apply_variables_protected(itm.client_secret)?,
                        consent_password: variables
                            .apply_variables_protected(itm.consent_password)?,
                        public_url: variables.apply_variables_opt(itm.public_url)?,
                        signing_key: variables.apply_variables_protected_opt(itm.signing_key)?,
                        signing_key_file: variables.apply_variables_opt(itm.signing_key_file)?,
                        access_token_ttl_sec: itm.access_token_ttl_sec,
                        refresh_token_ttl_sec: itm.refresh_token_ttl_sec,
                    },
                );
            }
        }

        Ok(())
    }

    fn populate_endpoint_templates(
        &mut self,
        settings_model: &mut SettingsModel,
        variables: &VariablesCompiled,
    ) -> Result<(), String> {
        if let Some(endpoint_templates) = settings_model.endpoint_templates.take() {
            for (key, itm) in endpoint_templates {
                self.endpoint_templates.insert(
                    variables.apply_variables(key)?,
                    EndpointTemplateSettings {
                        ssl_certificate: variables.apply_variables_opt(itm.ssl_certificate)?,
                        client_certificate_ca: variables
                            .apply_variables_opt(itm.client_certificate_ca)?,
                        google_auth: variables.apply_variables_opt(itm.google_auth)?,
                        oauth: variables.apply_variables_opt(itm.oauth)?,
                        modify_http_headers: super::populate_modify_http_headers_settings(
                            itm.modify_http_headers,
                            variables,
                        )?,
                        whitelisted_ip: variables.apply_variables_opt(itm.whitelisted_ip)?,
                        whitelisted_country: variables
                            .apply_variables_opt(itm.whitelisted_country)?,
                        api_keys_auth: variables.apply_variables_opt(itm.api_keys_auth)?,
                    },
                );
            }
        }

        Ok(())
    }

    fn populate_allowed_users(
        &mut self,
        settings_model: &mut SettingsModel,
        variables: &VariablesCompiled,
    ) -> Result<(), String> {
        if let Some(allowed_users) = settings_model.allowed_users.take() {
            for (key, users) in allowed_users {
                self.allowed_users.insert(
                    variables.apply_variables(key)?,
                    super::populate_vec_of_string(users, variables)?,
                );
            }
        }

        Ok(())
    }

    fn populate_ip_white_lists(
        &mut self,
        settings_model: &mut SettingsModel,
        variables: &VariablesCompiled,
    ) -> Result<(), String> {
        if let Some(ip_white_lists) = settings_model.ip_white_lists.take() {
            for (key, ip_list) in ip_white_lists {
                let key = variables.apply_variables(key)?;
                let ip_list = super::populate_vec_of_string(ip_list, variables)?;

                // A wrong entry fails the settings load with a word on it, rather than being left
                // out of the list without one.
                for entry in &ip_list {
                    crate::types::check_ip_white_list_entry(entry)
                        .map_err(|err| format!("ip_white_lists '{key}': {err}"))?;
                }

                self.ip_white_lists.insert(key, ip_list);
            }
        }

        Ok(())
    }

    fn populate_country_white_lists(
        &mut self,
        settings_model: &mut SettingsModel,
        variables: &VariablesCompiled,
    ) -> Result<(), String> {
        if let Some(country_white_lists) = settings_model.country_white_lists.take() {
            for (key, countries) in country_white_lists {
                self.country_white_lists.insert(
                    variables.apply_variables(key)?,
                    super::populate_vec_of_string(countries, variables)?,
                );
            }
        }

        Ok(())
    }

    fn populate_gateway_server(
        &mut self,
        settings_model: &mut SettingsModel,
        variables: &VariablesCompiled,
    ) -> Result<(), String> {
        if let Some(itm) = settings_model.gateway_server.take() {
            let mut authorized_keys = Vec::with_capacity(itm.authorized_keys.len());
            for path in itm.authorized_keys {
                authorized_keys.push(variables.apply_variables(path)?);
            }
            self.gateway_server = Some(GatewayServerSettings {
                port: itm.port,
                allowed_ip: itm.allowed_ip.clone(),
                authorized_keys,
                debug: itm.debug,
            });
        }

        Ok(())
    }

    fn populate_gateway_client(
        &mut self,
        settings_model: &mut SettingsModel,
        variables: &VariablesCompiled,
    ) -> Result<(), String> {
        if let Some(settings) = settings_model.gateway_clients.take() {
            for (key, itm) in settings {
                self.gateway_clients.insert(
                    variables.apply_variables(key)?,
                    GatewayClientSettings {
                        remote_host: variables.apply_variables(itm.remote_host)?,
                        ssh_credentials: variables.apply_variables_opt(itm.ssh_credentials)?,
                        private_key: variables.apply_variables_opt(itm.private_key)?,
                        compress: itm.compress,
                        debug: itm.debug,
                        allow_incoming_forward_connections: itm.allow_incoming_forward_connections,
                        connect_timeout: itm.connect_timeout,
                        sync_ssl_certificates: itm.sync_ssl_certificates,
                    },
                );
            }
        }

        Ok(())
    }
}

async fn load_includes(
    settings_model: &SettingsModel,
) -> Result<Vec<crate::settings::SettingsModel>, String> {
    let mut result = vec![];

    if let Some(include) = settings_model.include.as_ref() {
        for include_file in include {
            let settings =
                crate::settings::SettingsModel::load_async(Some(include_file.as_str())).await?;
            result.push(settings);
        }
    }

    // The dynamic settings file is merged like an include, but it is allowed to be
    // missing (it may not have been written yet via MCP) or blank — then it adds nothing.
    if let Some(dynamic_file) = settings_model.dynamic_configurations_file.as_ref() {
        if dynamic_configurations_file_exists(dynamic_file)? {
            if let Some(settings) =
                crate::settings::SettingsModel::load_dynamic_async(dynamic_file.as_str()).await?
            {
                result.push(settings);
            }
        }
    }

    Ok(result)
}

fn load_includes_block(
    settings_model: &SettingsModel,
) -> Result<Vec<crate::settings::SettingsModel>, String> {
    let mut result = vec![];

    if let Some(include) = settings_model.include.as_ref() {
        for include_file in include {
            let settings = crate::settings::SettingsModel::load(Some(include_file.as_str()))?;
            result.push(settings);
        }
    }

    // The dynamic settings file is merged like an include, but it is allowed to be
    // missing (it may not have been written yet via MCP) or blank — then it adds nothing.
    if let Some(dynamic_file) = settings_model.dynamic_configurations_file.as_ref() {
        if dynamic_configurations_file_exists(dynamic_file)? {
            if let Some(settings) =
                crate::settings::SettingsModel::load_dynamic(dynamic_file.as_str())?
            {
                result.push(settings);
            }
        }
    }

    Ok(result)
}

fn dynamic_configurations_file_exists(file_name: &str) -> Result<bool, String> {
    let path = crate::settings::expand_home(file_name)?;
    Ok(std::path::Path::new(path.as_str()).exists())
}

/// A host of the settings, with the variables put into its values - all but the entries of its
/// `additional_hosts`, which are left as they are written: each is taken or ignored on its own,
/// one with a variable which is not there as well (`get_additional_host_id`).
pub fn compile_host(
    host_id: String,
    host_settings: HostSettings,
    variables: &VariablesCompiled,
) -> Result<(String, HostSettings), String> {
    let host_id = variables.apply_variables(host_id)?;
    let locations = compile_locations(host_settings.locations, variables)?;

    let host_settings = HostSettings {
        additional_hosts: host_settings.additional_hosts,
        endpoint: EndpointSettings {
            endpoint_type: variables.apply_variables(host_settings.endpoint.endpoint_type)?,
            ssl_certificate: variables
                .apply_variables_opt(host_settings.endpoint.ssl_certificate)?,
            client_certificate_ca: variables
                .apply_variables_opt(host_settings.endpoint.client_certificate_ca)?,
            google_auth: variables.apply_variables_opt(host_settings.endpoint.google_auth)?,
            oauth: variables.apply_variables_opt(host_settings.endpoint.oauth)?,
            modify_http_headers: super::populate_modify_http_headers_settings(
                host_settings.endpoint.modify_http_headers,
                variables,
            )?,
            debug: host_settings.endpoint.debug,
            inject_country: host_settings.endpoint.inject_country,
            cloudflare: host_settings.endpoint.cloudflare,
            request_with_header_only: compile_request_with_header_only(
                host_settings.endpoint.request_with_header_only,
                variables,
            )?,
            whitelisted_ip: variables.apply_variables_opt(host_settings.endpoint.whitelisted_ip)?,
            whitelisted_country: variables
                .apply_variables_opt(host_settings.endpoint.whitelisted_country)?,
            template_id: variables.apply_variables_opt(host_settings.endpoint.template_id)?,
            allowed_users: variables.apply_variables_opt(host_settings.endpoint.allowed_users)?,
            api_keys_auth: variables.apply_variables_opt(host_settings.endpoint.api_keys_auth)?,
            keep_alive: host_settings.endpoint.keep_alive,
            track_metrics_by_all_domains: host_settings.endpoint.track_metrics_by_all_domains,
            hsts: host_settings.endpoint.hsts,
            mcp_buffer_size: variables
                .apply_variables_opt(host_settings.endpoint.mcp_buffer_size)?,
            timeouts: host_settings.endpoint.timeouts,
        },
        locations,
    };

    Ok((host_id, host_settings))
}

/// `request_with_header_only:` with the variables put into its names and values - a value is a
/// secret, kept best in a variable. An error never tells a value.
fn compile_request_with_header_only(
    settings: Option<RequestWithHeaderOnlySettings>,
    variables: &VariablesCompiled,
) -> Result<Option<RequestWithHeaderOnlySettings>, String> {
    let Some(settings) = settings else {
        return Ok(None);
    };

    let mut result = Vec::with_capacity(settings.0.len());

    for item in settings.0 {
        let mut compiled = std::collections::BTreeMap::new();

        for (name, value) in item {
            let name = variables.apply_variables(name)?;
            let value = variables
                .apply_variables_protected(value)
                .map_err(|err| format!("request_with_header_only: the value of '{name}': {err}"))?;

            if compiled.insert(name.clone(), value).is_some() {
                return Err(format!("request_with_header_only: '{name}' is named twice"));
            }
        }

        result.push(compiled);
    }

    Ok(Some(RequestWithHeaderOnlySettings(result)))
}

fn compile_locations(
    locations: Vec<LocationSettings>,
    variables: &VariablesCompiled,
) -> Result<Vec<LocationSettings>, String> {
    let mut result = Vec::with_capacity(locations.len());

    for location in locations {
        if location.auth_header.is_some() {
            return Err(format!(
                "Location '{}': auth_header is removed. A location is guarded with api keys now: 'api_keys_auth: <id>' names a set of 'api_keys:', and the key comes in the 'X-Api-Key' header",
                location.path.as_deref().unwrap_or("/")
            ));
        }

        result.push(LocationSettings {
            path: variables.apply_variables_opt(location.path)?,
            proxy_pass_to: variables.apply_variables_opt(location.proxy_pass_to)?,
            location_type: variables.apply_variables_opt(location.location_type)?,
            domain_name: variables.apply_variables_opt(location.domain_name)?,
            modify_http_headers: super::populate_modify_http_headers_settings(
                location.modify_http_headers,
                variables,
            )?,
            default_file: variables.apply_variables_opt(location.default_file)?,
            status_code: location.status_code,
            content_type: variables.apply_variables_opt(location.content_type)?,
            body: variables.apply_variables_opt(location.body)?,
            whitelisted_ip: variables.apply_variables_opt(location.whitelisted_ip)?,
            whitelisted_country: variables.apply_variables_opt(location.whitelisted_country)?,
            compress: location.compress,
            trace_payload: location.trace_payload,
            api_keys_auth: variables.apply_variables_opt(location.api_keys_auth)?,
            auth_header: None,
            allowed_hosts: location.allowed_hosts,
            strip_path: location.strip_path,
            timeouts: location.timeouts,
        });
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The main file names no hosts and includes the files which do: the hosts of all of them
    /// are there once the settings are put together.
    #[test]
    fn the_hosts_may_all_be_in_the_included_files() {
        let dir = std::env::temp_dir().join(format!(
            "my-reverse-proxy-hosts-in-includes-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();

        let host = |port: u16| {
            format!(
                "  localhost:{port}:\n    endpoint:\n      type: http\n    locations:\n    - proxy_pass_to: http://127.0.0.1:9000\n"
            )
        };

        let first = dir.join("first.yaml");
        std::fs::write(&first, format!("hosts:\n{}", host(8001))).unwrap();

        let second = dir.join("second.yaml");
        std::fs::write(&second, format!("hosts:\n{}{}", host(8002), host(8003))).unwrap();

        // A file of variables and nothing else: no hosts in it either.
        let third = dir.join("third.yaml");
        std::fs::write(&third, "variables:\n  ENV: dev\n").unwrap();

        let main = dir.join("main.yaml");
        std::fs::write(
            &main,
            format!(
                "include:\n- {}\n- {}\n- {}\n",
                first.display(),
                second.display(),
                third.display()
            ),
        )
        .unwrap();

        let settings_model = SettingsModel::load(Some(main.to_str().unwrap())).unwrap();
        let include_settings = load_includes_block(&settings_model).unwrap();

        let mut compiled = SettingsCompiled::default();
        compiled.populate(settings_model, include_settings).unwrap();

        let _ = std::fs::remove_dir_all(&dir);

        let mut hosts: Vec<_> = compiled.hosts.keys().cloned().collect();
        hosts.sort();
        assert_eq!(
            hosts,
            vec!["localhost:8001", "localhost:8002", "localhost:8003"]
        );
    }

    /// Settings files in a directory of their own: `main.yaml` with `main` in it, and each of
    /// `others` - its name and its content - which `main` can include.
    fn compile_files(
        name: &str,
        main: &str,
        others: &[(&str, &str)],
    ) -> Result<SettingsCompiled, String> {
        let dir =
            std::env::temp_dir().join(format!("my-reverse-proxy-{name}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();

        let mut main = main.to_string();
        for (file_name, content) in others {
            let path = dir.join(file_name);
            std::fs::write(&path, content).unwrap();
            main = main.replace(file_name, path.to_str().unwrap());
        }

        let main_path = dir.join("main.yaml");
        std::fs::write(&main_path, main).unwrap();

        let result = SettingsModel::load(Some(main_path.to_str().unwrap())).and_then(|model| {
            let include_settings = load_includes_block(&model)?;
            let mut compiled = SettingsCompiled::default();
            compiled.populate(model, include_settings)?;
            Ok(compiled)
        });

        let _ = std::fs::remove_dir_all(&dir);
        result
    }

    /// The urls are written with the variables of the settings - the ones of the files it
    /// includes as well - and the variables are kept for the hosts the urls give.
    #[test]
    fn real_time_configurations_is_read_with_the_variables_of_the_settings() {
        let compiled = compile_files(
            "real-time-configurations",
            "variables:\n  hosts_api: 10.0.0.7:5000\ninclude:\n- other.yaml\nreal_time_configurations:\n  refresh_interval: 30000\n  urls:\n  - http://${hosts_api}/hosts?env=${env}\n  - http://${hosts_api}/keys\n",
            &[("other.yaml", "variables:\n  env: dev\n")],
        )
        .unwrap();

        let real_time_configurations = compiled.real_time_configurations.as_ref().unwrap();
        assert_eq!(
            real_time_configurations.urls,
            [
                "http://10.0.0.7:5000/hosts?env=dev",
                "http://10.0.0.7:5000/keys"
            ]
        );
        assert_eq!(
            real_time_configurations.get_refresh_interval(),
            std::time::Duration::from_secs(30)
        );
        assert_eq!(
            compiled
                .variables
                .apply_variables("${env}".to_string())
                .unwrap(),
            "dev"
        );
    }

    /// The value of a header of `request_with_header_only` is a secret, kept best in a variable:
    /// the variable is put in - and one which is not there refuses the host, without a value.
    #[test]
    fn request_with_header_only_takes_the_secret_from_a_variable() {
        let host = |value: &str| {
            format!(
                "hosts:\n  localhost:8001:\n    endpoint:\n      type: https2\n      request_with_header_only:\n      - X-Zone-Secret: {value}\n    locations:\n    - proxy_pass_to: http://127.0.0.1:9000\n"
            )
        };

        let compiled = compile_files(
            "request-with-header-only",
            &format!(
                "variables:\n  zone_secret: s3cr3t-of-the-zone\n{}",
                host("${zone_secret}")
            ),
            &[],
        )
        .unwrap();

        let headers: Vec<(String, String)> = compiled.hosts["localhost:8001"]
            .endpoint
            .request_with_header_only
            .as_ref()
            .unwrap()
            .iter()
            .map(|(name, value)| (name.to_string(), value.as_str().to_string()))
            .collect();

        assert_eq!(
            headers,
            vec![(
                "X-Zone-Secret".to_string(),
                "s3cr3t-of-the-zone".to_string()
            )]
        );

        let err = compile_files(
            "request-with-header-only-no-variable",
            &host("${zone_secret_which_is_not_there}"),
            &[],
        )
        .unwrap_err();
        assert!(
            err.contains("request_with_header_only: the value of 'X-Zone-Secret'"),
            "{err}"
        );
    }

    #[test]
    fn real_time_configurations_is_not_required() {
        let compiled = compile_files("no-real-time-configurations", "hosts: {}\n", &[]).unwrap();
        assert!(compiled.real_time_configurations.is_none());
    }

    /// Two lists would be one of them, depending on the order the files are read in.
    #[test]
    fn real_time_configurations_in_two_files_refuses_the_settings() {
        let err = compile_files(
            "real-time-configurations-twice",
            "include:\n- other.yaml\nreal_time_configurations:\n  urls:\n  - http://10.0.0.7/hosts\n",
            &[(
                "other.yaml",
                "real_time_configurations:\n  urls:\n  - http://10.0.0.8/hosts\n",
            )],
        )
        .unwrap_err();

        assert!(
            err.contains("real_time_configurations is declared more than once"),
            "{err}"
        );
    }

    #[test]
    fn real_time_configurations_which_can_not_work_refuses_the_settings() {
        let err = compile_files(
            "real-time-configurations-interval",
            "real_time_configurations:\n  urls:\n  - http://10.0.0.7/hosts\n  refresh_interval: 5\n",
            &[],
        )
        .unwrap_err();

        assert!(err.contains("refresh_interval"), "{err}");
    }

    /// The hosts of the url are not left out without a word: the settings say what it is called
    /// now.
    #[test]
    fn dynamic_hosts_refuses_the_settings_with_its_new_name() {
        let err = compile_files(
            "dynamic-hosts-renamed",
            "dynamic_hosts:\n  url: http://10.0.0.7/hosts\n",
            &[],
        )
        .unwrap_err();

        assert!(err.contains("real_time_configurations"), "{err}");
    }

    /// A set is put together from every file which declares keys under its id - the dynamic
    /// settings file is one of them, read as an include.
    #[test]
    fn the_keys_of_one_id_in_several_files_make_one_set() {
        let compiled = compile_files(
            "api-keys-merged",
            "variables:\n  ci_key: ci-key-value\ninclude:\n- other.yaml\napi_keys:\n  mcp_clients:\n  - desktop-key\n  - ${ci_key}\n  admins:\n  - admin-key\n",
            &[(
                "other.yaml",
                "api_keys:\n  mcp_clients:\n  - desktop-key\n  - tenant-key\n  empty: []\n",
            )],
        )
        .unwrap();

        let mut clients = compiled.api_keys["mcp_clients"].clone();
        clients.sort();
        assert_eq!(clients, ["ci-key-value", "desktop-key", "tenant-key"]);
        assert_eq!(compiled.api_keys["admins"], ["admin-key"]);
        assert!(compiled.api_keys["empty"].is_empty());
    }

    #[test]
    fn a_set_of_keys_which_can_not_work_refuses_the_settings() {
        for (name, main) in [
            ("api-keys-none", "api_keys:\n  none:\n  - key\n"),
            (
                "api-keys-upper-variable",
                "api_keys:\n  clients:\n  - ${MCP_KEY}\n",
            ),
            (
                "api-keys-missing-variable",
                "api_keys:\n  clients:\n  - ${not_declared}\n",
            ),
            ("api-keys-empty-key", "api_keys:\n  clients:\n  - ''\n"),
        ] {
            let err = compile_files(name, main, &[]).unwrap_err();
            assert!(err.contains("api_keys"), "{main}: {err}");
        }
    }

    /// A location with `auth_header` left in would be open to everybody without a word.
    #[test]
    fn auth_header_refuses_the_settings() {
        let err = compile_files(
            "auth-header-removed",
            "hosts:\n  localhost:8000:\n    endpoint:\n      type: http\n    locations:\n    - path: /mcp\n      proxy_pass_to: http://127.0.0.1:9000\n      auth_header: Bearer secret\n",
            &[],
        )
        .unwrap_err();

        assert!(err.contains("auth_header is removed"), "{err}");
        assert!(err.contains("api_keys_auth"), "{err}");
        assert!(!err.contains("secret"), "{err}");
    }

    #[test]
    fn api_keys_auth_is_read_with_the_variables_of_the_settings() {
        let compiled = compile_files(
            "api-keys-auth-variables",
            "variables:\n  keys_id: mcp_clients\nhosts:\n  localhost:8000:\n    endpoint:\n      type: http\n      api_keys_auth: ${keys_id}\n    locations:\n    - path: /open\n      proxy_pass_to: http://127.0.0.1:9000\n      api_keys_auth: none\nendpoint_templates:\n  tpl:\n    api_keys_auth: ${keys_id}\n",
            &[],
        )
        .unwrap();

        let host = &compiled.hosts["localhost:8000"];
        assert_eq!(host.endpoint.api_keys_auth.as_deref(), Some("mcp_clients"));
        assert_eq!(host.locations[0].api_keys_auth.as_deref(), Some("none"));
        assert_eq!(
            compiled.endpoint_templates["tpl"].api_keys_auth.as_deref(),
            Some("mcp_clients")
        );
    }

    /// The control port would listen on every address if a typo were taken for no value: the
    /// settings are refused instead.
    #[test]
    fn an_http_control_ip_which_is_not_an_address_refuses_the_settings() {
        let dir = std::env::temp_dir().join(format!(
            "my-reverse-proxy-http-control-ip-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();

        let main = dir.join("main.yaml");
        std::fs::write(
            &main,
            "global_settings:\n  http_control_port: 9000\n  http_control_ip: 127.0.0.l\n",
        )
        .unwrap();

        let settings_model = SettingsModel::load(Some(main.to_str().unwrap())).unwrap();
        let include_settings = load_includes_block(&settings_model).unwrap();

        let mut compiled = SettingsCompiled::default();
        let err = compiled
            .populate(settings_model, include_settings)
            .unwrap_err();

        let _ = std::fs::remove_dir_all(&dir);

        assert_eq!(
            err,
            "global_settings.http_control_ip: '127.0.0.l' is not a valid ip address"
        );
    }

    const HOST: &str = "    endpoint:\n      type: https2\n      ssl_certificate: wildcard\n    locations:\n    - proxy_pass_to: http://127.0.0.1:9000\n";

    fn names_of(compiled: &SettingsCompiled) -> Vec<(&str, &str)> {
        compiled
            .additional_hosts
            .iter()
            .map(|(name, itm)| {
                assert!(!itm.dynamic, "{name}");
                (name.as_str(), itm.host_id.as_str())
            })
            .collect()
    }

    fn sorted_hosts(compiled: &SettingsCompiled) -> Vec<&str> {
        let mut result: Vec<&str> = compiled.hosts.keys().map(|itm| itm.as_str()).collect();
        result.sort();
        result
    }

    /// The `additional_hosts` of a host are names of it on its port - not hosts of their own.
    /// Variables are put into them as well.
    #[test]
    fn the_additional_hosts_of_the_files_are_names_of_their_host() {
        let compiled = compile_files(
            "additional-hosts",
            &format!(
                "variables:\n  env: dev\nhosts:\n  example.com:443:\n    additional_hosts:\n    - www.example.com\n    - ${{env}}.example.com\n    - api.example.com:443\n{HOST}"
            ),
            &[],
        )
        .unwrap();

        assert_eq!(sorted_hosts(&compiled), ["example.com:443"]);
        assert!(compiled.hosts["example.com:443"].additional_hosts.is_none());
        assert_eq!(
            names_of(&compiled),
            [
                ("api.example.com:443", "example.com:443"),
                ("dev.example.com:443", "example.com:443"),
                ("www.example.com:443", "example.com:443"),
            ]
        );
        assert!(compiled.additional_host_errors.is_empty());

        for host_id in ["www.example.com:443", "API.example.com:443"] {
            assert!(compiled.is_static_host(host_id));
            assert_eq!(
                compiled.get_host_group(host_id),
                [
                    "example.com:443",
                    "api.example.com:443",
                    "dev.example.com:443",
                    "www.example.com:443"
                ]
            );
        }
    }

    /// An entry which can not be served is ignored with why, under the host whose list has it:
    /// the rest of the settings is loaded.
    #[test]
    fn an_entry_which_can_not_be_served_is_ignored() {
        let compiled = compile_files(
            "additional-hosts-ignored",
            &format!(
                "hosts:\n  example.com:443:\n    additional_hosts:\n    - www.example.com\n    - www.example.com:8443\n    - '*.example.com'\n    - ${{not_there}}.example.com\n    - WWW.example.com\n    - other.example.com\n    - example.com\n{HOST}  other.example.com:443:\n{HOST}  db.example.com:5432:\n    additional_hosts:\n    - db2.example.com\n    endpoint:\n      type: tcp\n    locations:\n    - proxy_pass_to: 127.0.0.1:5433\n"
            ),
            &[],
        )
        .unwrap();

        assert_eq!(
            sorted_hosts(&compiled),
            [
                "db.example.com:5432",
                "example.com:443",
                "other.example.com:443"
            ]
        );
        assert_eq!(
            names_of(&compiled),
            [("www.example.com:443", "example.com:443")]
        );

        let errors = &compiled.additional_host_errors["example.com:443"];
        for (entry, why) in [
            ("www.example.com:8443", "on port 8443"),
            ("*.example.com", "not a domain name"),
            ("${not_there}.example.com", "not_there"),
            ("WWW.example.com", "in the list twice"),
            ("other.example.com", "the settings have a host with this id"),
            ("example.com", "the settings have a host with this id"),
        ] {
            assert!(
                errors
                    .iter()
                    .any(|err| err.contains(&format!("'{entry}' is ignored")) && err.contains(why)),
                "{entry}: {errors:?}"
            );
        }
        assert_eq!(errors.len(), 6, "{errors:?}");

        assert!(compiled.additional_host_errors["db.example.com:5432"][0].contains("type: tcp"));
    }

    /// A name in the lists of two hosts is served by neither: which one would serve it is not
    /// to depend on the order the files are read in - and it is decided the same way at every
    /// load.
    #[test]
    fn a_name_in_the_lists_of_two_hosts_is_ignored_by_both() {
        for attempt in 0..20 {
            let compiled = compile_files(
                &format!("additional-hosts-two-{attempt}"),
                &format!(
                    "include:\n- other.yaml\nhosts:\n  example.com:443:\n    additional_hosts:\n    - www.example.com\n    - api.example.com\n{HOST}"
                ),
                &[(
                    "other.yaml",
                    &format!(
                        "hosts:\n  other.example.com:443:\n    additional_hosts:\n    - WWW.example.com\n{HOST}"
                    ),
                )],
            )
            .unwrap();

            assert_eq!(
                names_of(&compiled),
                [("api.example.com:443", "example.com:443")]
            );

            for host_id in ["example.com:443", "other.example.com:443"] {
                let errors = &compiled.additional_host_errors[host_id];
                assert_eq!(errors.len(), 1, "{host_id}: {errors:?}");
                assert!(errors[0].contains("served by one host only"), "{errors:?}");
            }
        }
    }

    /// A host written again in another file replaces the one before, as it always has: the
    /// names of that one go with it - also when the later file has one of them as a host. The
    /// order the hosts of a file are read in decides nothing.
    #[test]
    fn a_host_written_again_takes_the_names_of_the_one_before_away() {
        for attempt in 0..20 {
            let compiled = compile_files(
                &format!("additional-hosts-replaced-{attempt}"),
                &format!(
                    "include:\n- other.yaml\nhosts:\n  example.com:443:\n    additional_hosts:\n    - www.example.com\n    - old.example.com\n{HOST}"
                ),
                &[(
                    "other.yaml",
                    &format!(
                        "hosts:\n  example.com:443:\n    additional_hosts:\n    - api.example.com\n{HOST}  www.example.com:443:\n{HOST}"
                    ),
                )],
            )
            .unwrap();

            assert_eq!(
                sorted_hosts(&compiled),
                ["example.com:443", "www.example.com:443"]
            );
            assert_eq!(
                names_of(&compiled),
                [("api.example.com:443", "example.com:443")]
            );
            assert!(compiled.additional_host_errors.is_empty());
        }
    }
}

#[cfg(test)]
mod ip_list_tests {
    use super::*;

    fn compile(yaml: &str) -> Result<SettingsCompiled, String> {
        let model = crate::settings::SettingsModel::parse_for_tests(yaml);
        let mut result = SettingsCompiled::default();
        result.populate(model, Vec::new())?;
        Ok(result)
    }

    #[test]
    fn a_subnet_is_an_entry_of_an_ip_list() {
        let settings =
            compile("ip_white_lists:\n  office:\n  - 10.0.0.0/24\n  - 192.168.1.7\n").unwrap();

        assert_eq!(
            settings.get_ip_white_list("office").unwrap(),
            ["10.0.0.0/24", "192.168.1.7"]
        );
    }

    /// A wrong entry used to panic the proxy when its list was loaded: it fails the settings load
    /// now, with the list it is in.
    #[test]
    fn a_wrong_entry_fails_the_settings_load() {
        let err = compile("ip_white_lists:\n  office:\n  - 10.0.0.0/33\n")
            .err()
            .unwrap();
        assert!(err.contains("ip_white_lists 'office'"), "{err}");
        assert!(err.contains("10.0.0.0/33"), "{err}");

        let err = compile("global_settings:\n  ip_blocklist_white_list:\n  - 10.0.0.0/x\n")
            .err()
            .unwrap();
        assert!(
            err.contains("global_settings.ip_blocklist_white_list"),
            "{err}"
        );

        assert!(compile("global_settings:\n  ip_blocklist_white_list:\n  - 10.0.0.0/8\n").is_ok());
    }
}
