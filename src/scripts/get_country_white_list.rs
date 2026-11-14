use std::sync::Arc;

use crate::{settings::*, settings_compiled::SettingsCompiled, types::CountryWhiteList};

/// The list of `country_white_lists` a `whitelisted_country` names. It has to be declared, as a
/// list of `ip_white_lists` has to be - a host which names one that is not does not load.
pub fn get_country_white_list(
    settings_model: &SettingsCompiled,
    id: &str,
) -> Result<Arc<CountryWhiteList>, String> {
    let Some(countries) = settings_model.country_white_lists.get(id) else {
        return Err(format!(
            "whitelisted_country: '{id}' is not in country_white_lists"
        ));
    };

    Ok(Arc::new(CountryWhiteList::new(id, countries)?))
}

/// `whitelisted_country` of the endpoint, or else of its template.
pub fn get_endpoint_whitelisted_country(
    settings_model: &SettingsCompiled,
    host_settings: &HostSettings,
) -> Result<Option<Arc<CountryWhiteList>>, String> {
    let id = super::get_from_host_or_templates(
        settings_model,
        host_settings,
        |host_settings| host_settings.endpoint.whitelisted_country.as_ref(),
        |templates| templates.whitelisted_country.as_ref(),
    )?;

    id.map(|id| get_country_white_list(settings_model, id))
        .transpose()
}

/// `whitelisted_country` of a location.
pub fn get_location_whitelisted_country(
    settings_model: &SettingsCompiled,
    location_settings: &LocationSettings,
) -> Result<Option<Arc<CountryWhiteList>>, String> {
    location_settings
        .whitelisted_country
        .as_deref()
        .map(|id| get_country_white_list(settings_model, id))
        .transpose()
}
