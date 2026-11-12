use crate::{configurations::EndpointHttpHostString, settings_compiled::SettingsCompiled};

/// Reloads one host from the settings files. The host and the hosts of its `additional_hosts`
/// are one configuration: they are reloaded together - whichever of them is named - and the
/// ones it was served under before which the settings do not have any more go.
pub async fn reload_endpoint_configuration(host_id_to_refresh: &str) -> Result<String, String> {
    let _apply_lock = crate::app::APP_CTX.settings_apply_lock.lock().await;

    let settings_model = SettingsCompiled::load_settings().await?;

    let group = settings_model.get_host_group(host_id_to_refresh);

    // What the last reload of the settings served with this configuration.
    let gone: Vec<String> = match crate::app::APP_CTX.applied_settings.load_full() {
        Some(applied) => applied
            .get_host_group(host_id_to_refresh)
            .into_iter()
            .filter(|host_id| !has_host(&settings_model, host_id))
            .collect(),
        None => Vec::new(),
    };

    if group.is_empty() {
        let mut result =
            crate::scripts::delete_http_endpoint_if_exists(&settings_model, host_id_to_refresh)
                .await;

        for host_id in &gone {
            if !host_id.eq_ignore_ascii_case(host_id_to_refresh) {
                let _ =
                    crate::scripts::delete_http_endpoint_if_exists(&settings_model, host_id).await;
                result = Ok(());
            }
        }

        return match result {
            Ok(_) => {
                crate::scripts::sync_endpoints().await;
                Ok(format!(
                    "Host configuration {} has been reloaded",
                    host_id_to_refresh
                ))
            }
            Err(_) => Err(format!(
                "Host configuration {} not found",
                host_id_to_refresh
            )),
        };
    }

    let mut errors: Vec<(&String, String)> = Vec::new();

    for host_id in &group {
        let result = match EndpointHttpHostString::new(host_id.to_string()) {
            Ok(host_endpoint) => {
                crate::scripts::update_host_configuration(
                    &settings_model,
                    host_endpoint,
                    &settings_model.hosts[host_id],
                )
                .await
            }
            Err(err) => Err(err),
        };

        if let Err(err) = result {
            errors.push((host_id, err));
        }
    }

    for host_id in &gone {
        if let Err(err) =
            crate::scripts::delete_http_endpoint_if_exists(&settings_model, host_id).await
        {
            errors.push((host_id, err));
        }
    }

    crate::scripts::sync_endpoints().await;

    // One host, as before: its error as it is.
    if group.len() == 1 && gone.is_empty() {
        if let Some((_, err)) = errors.pop() {
            return Err(err);
        }
    }

    if !errors.is_empty() {
        let errors: Vec<String> = errors
            .into_iter()
            .map(|(host_id, err)| format!("{host_id}: {err}"))
            .collect();

        return Err(format!(
            "Host configuration {} is reloaded in part: {}",
            host_id_to_refresh,
            errors.join("; ")
        ));
    }

    Ok(format!(
        "Host configuration {} has been reloaded",
        host_id_to_refresh
    ))
}

fn has_host(settings_model: &SettingsCompiled, host_id: &str) -> bool {
    settings_model
        .hosts
        .keys()
        .any(|existing| existing.eq_ignore_ascii_case(host_id))
}
