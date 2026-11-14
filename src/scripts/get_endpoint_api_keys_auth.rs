use crate::{settings::*, settings_compiled::SettingsCompiled};

/// `api_keys_auth` of the endpoint of `host_settings`: its own, or else the one of its template.
/// `none` is returned as it is: it opens the locations which name no set of their own.
pub fn get_endpoint_api_keys_auth<'s>(
    settings_model: &'s SettingsCompiled,
    host_settings: &'s HostSettings,
) -> Result<Option<&'s str>, String> {
    let result = super::get_from_host_or_templates(
        settings_model,
        host_settings,
        |host_settings| host_settings.endpoint.api_keys_auth.as_ref(),
        |templates| templates.api_keys_auth.as_ref(),
    )?;

    Ok(result.map(|itm| itm.as_str()))
}

/// Whether a location of the endpoint is guarded by api keys - which an endpoint with no HTTP
/// layer (`type: tcp`, `type: mcp`) has no way to check.
pub fn endpoint_has_api_keys_auth(
    settings_model: &SettingsCompiled,
    host_settings: &HostSettings,
) -> Result<bool, String> {
    let endpoint = get_endpoint_api_keys_auth(settings_model, host_settings)?;

    Ok(host_settings.locations.iter().any(|location| {
        crate::api_keys::resolve_api_keys_auth(location.api_keys_auth.as_deref(), endpoint)
            .is_some()
    }))
}
