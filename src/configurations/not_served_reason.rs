/// Why an endpoint serves nobody: it was given an access setting it has no way to apply.
///
/// Such settings load - an endpoint written wrong does not take the others down with it. But
/// the endpoint does not serve: otherwise its operator takes it for a guarded one while it is
/// open to everybody. Every request is refused without a word, and a source listed in
/// `global_settings.debug_ip` is told the reason instead.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotServedReason(String);

impl NotServedReason {
    /// `None`: `settings` is empty - there is nothing the endpoint can not apply.
    ///
    /// `settings`: the names of the settings, as they are written in a settings file. `why`:
    /// what about the endpoint makes them impossible to apply. `advice`: what to do about it.
    pub fn new(
        host_endpoint: &str,
        endpoint_type: &str,
        settings: &[&str],
        why: &str,
        advice: &str,
    ) -> Option<Self> {
        if settings.is_empty() {
            return None;
        }

        let settings = settings
            .iter()
            .map(|setting| format!("'{setting}'"))
            .collect::<Vec<_>>()
            .join(", ");

        Some(Self(format!(
            "Endpoint '{host_endpoint}' is 'type: {endpoint_type}', {why}, so {settings} can not \
             be applied to it. The endpoint serves nobody until this is fixed: {advice}"
        )))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nothing_to_apply_is_no_reason() {
        assert_eq!(
            NotServedReason::new("localhost:443", "mcp", &[], "why", "advice"),
            None
        );
    }

    #[test]
    fn the_reason_names_the_endpoint_and_every_setting() {
        let reason = NotServedReason::new(
            "localhost:443",
            "mcp",
            &["auth_header", "google_auth"],
            "a raw bridge with no HTTP layer",
            "remove the setting",
        )
        .unwrap();

        assert_eq!(
            reason.as_str(),
            "Endpoint 'localhost:443' is 'type: mcp', a raw bridge with no HTTP layer, so \
             'auth_header', 'google_auth' can not be applied to it. The endpoint serves nobody \
             until this is fixed: remove the setting"
        );
    }
}
