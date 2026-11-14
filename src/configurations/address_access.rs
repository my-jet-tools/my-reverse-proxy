use crate::types::{ConnectionIp, CountryWhiteList};

/// `whitelisted_ip` and `whitelisted_country` of an endpoint or of a location, for the client at
/// `connection_ip`: it has to be in each list that is named - adding a list never lets in anybody
/// the other one keeps out. A connection with no address (a unix socket) is restricted by
/// neither.
///
/// Why the client is refused, for a log - `None`: it is not.
pub async fn client_address_refusal(
    ip_list_id: Option<&str>,
    country_list: Option<&CountryWhiteList>,
    connection_ip: &ConnectionIp,
) -> Option<String> {
    if ip_list_id.is_none() && country_list.is_none() {
        return None;
    }

    let client_ip = connection_ip.get_ip_addr()?;

    if let Some(ip_list_id) = ip_list_id {
        let is_whitelisted = crate::app::APP_CTX
            .current_configuration
            .get(|config| {
                config
                    .white_list_ip_list
                    .is_white_listed(ip_list_id, &client_ip)
            })
            .await;

        if !is_whitelisted {
            return Some(format!("client IP is not in ip list '{ip_list_id}'"));
        }
    }

    country_list.and_then(|list| list.refusal(client_ip))
}
