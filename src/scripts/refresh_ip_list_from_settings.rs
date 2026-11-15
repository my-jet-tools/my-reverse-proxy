use crate::{settings_compiled::SettingsCompiled, types::WhiteListedIpList};

/// Puts the list `white_list_ip_id` of the settings into the live configuration. A list the
/// settings do not declare is taken out of it: an endpoint or a location naming it lets nobody in
/// (and the host loads all the same).
pub async fn refresh_ip_list_from_settings(
    settings_model: &SettingsCompiled,
    white_list_ip_id: &str,
) -> Result<(), String> {
    let Some(ip_list) = settings_model.ip_white_lists.get(white_list_ip_id) else {
        println!(
            "whitelisted_ip: '{white_list_ip_id}' is not in ip_white_lists - nobody is let in by it"
        );

        crate::app::APP_CTX
            .current_configuration
            .write(|config| config.white_list_ip_list.remove(white_list_ip_id))
            .await;

        return Ok(());
    };

    let white_list_ip_list = WhiteListedIpList::new(ip_list);

    crate::app::APP_CTX
        .current_configuration
        .write(|config| {
            config
                .white_list_ip_list
                .insert_or_update(white_list_ip_id.to_string(), white_list_ip_list)
        })
        .await;

    Ok(())
}
