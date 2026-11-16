use std::{collections::HashMap, mem};

use rust_common::placeholders::*;

use crate::{settings::SettingsModel, types::ProtectedString};

/// The variables of the settings files. A value may be a secret - the value of a header of
/// `request_with_header_only`, a password -, so each is a [`ProtectedString`] from the moment the
/// settings are read: `{:?}` shows the names alone, the values as `***`.
#[derive(Default, Clone, Debug)]
pub struct VariablesCompiled {
    data: HashMap<String, ProtectedString>,
}

/// What is told of a variable a later settings file writes over: its name, the values as `***`.
fn overriding_message(key: &str) -> String {
    let masked = ProtectedString::MASK;
    format!("Overriding variable '{masked}' to '{masked}' for key '{key}'")
}

impl VariablesCompiled {
    pub fn merge(&mut self, settings: &mut SettingsModel) {
        if let Some(variables) = mem::take(&mut settings.variables) {
            for (key, value) in variables {
                if self.data.contains_key(&key) {
                    println!("{}", overriding_message(&key));
                }
                self.data.insert(key, value);
            }
        }
    }

    pub fn apply_variables_opt(&self, value: Option<String>) -> Result<Option<String>, String> {
        let value = match value {
            Some(value) => value,
            None => return Ok(None),
        };

        let result = self.apply_variables(value)?;
        Ok(Some(result.to_string()))
    }

    /// [`Self::apply_variables`] of a secret: it stays one.
    pub fn apply_variables_protected(
        &self,
        value: ProtectedString,
    ) -> Result<ProtectedString, String> {
        self.apply_variables(value.into_string())
            .map(ProtectedString::from)
    }

    /// [`Self::apply_variables_protected`] of a secret which may not be set.
    pub fn apply_variables_protected_opt(
        &self,
        value: Option<ProtectedString>,
    ) -> Result<Option<ProtectedString>, String> {
        value
            .map(|value| self.apply_variables_protected(value))
            .transpose()
    }

    pub fn apply_variables(&self, value: String) -> Result<String, String> {
        if !value.contains("${") {
            return Ok(value);
        }

        let mut result = String::new();

        let placeholders_iterator =
            rust_common::placeholders::PlaceholdersIterator::new(&value, "${", "}");

        for itm in placeholders_iterator {
            match itm {
                ContentToken::Text(text) => {
                    result.push_str(text);
                }
                ContentToken::Placeholder(placeholder) => {
                    match name_characteristics(placeholder)? {
                        VariableNameType::Reserved => {
                            result.push_str("${");
                            result.push_str(placeholder);
                            result.push('}');
                            continue;
                        }
                        VariableNameType::Variable => {
                            if let Some(value) = self.data.get(placeholder) {
                                result.push_str(value.as_str());
                                continue;
                            }

                            if let Ok(value) = std::env::var(placeholder) {
                                result.push_str(value.as_str());
                                continue;
                            }
                        }
                    }

                    return Err(format!("Variable {} not found", placeholder));
                }
            }
        }

        Ok(result)
    }
}

pub enum VariableNameType {
    Reserved,
    Variable,
}

fn name_characteristics(src: &str) -> Result<VariableNameType, String> {
    let mut has_upper_case = false;
    let mut has_lower_case = false;

    for c in src.chars() {
        if c.is_ascii_uppercase() {
            has_upper_case = true;
        } else if c.is_ascii_lowercase() {
            has_lower_case = true;
        }

        if has_upper_case && has_lower_case {
            return Err(format!(
                "Env variable {} has to be ether UPPER_CASED or lower_cased",
                src
            ));
        }
    }

    if has_upper_case {
        return Ok(VariableNameType::Reserved);
    }

    Ok(VariableNameType::Variable)
}

#[cfg(test)]
mod tests {
    use super::VariablesCompiled;

    /// A value may be a secret: neither the message of a variable written over nor `{:?}` has it.
    #[test]
    fn a_value_of_a_variable_is_never_written_out() {
        let mut variables = VariablesCompiled::default();

        for value in ["first-s3cr3t", "second-s3cr3t"] {
            let mut settings: crate::settings::SettingsModel =
                my_settings_reader::serde_yaml::from_str(&format!(
                    "variables:\n  zone_secret: {value}\n  env: dev\n"
                ))
                .unwrap();
            variables.merge(&mut settings);
        }

        // The later file wins, as it always has.
        assert_eq!(
            variables
                .apply_variables("${zone_secret}".to_string())
                .unwrap(),
            "second-s3cr3t"
        );

        let message = super::overriding_message("zone_secret");
        assert_eq!(
            message,
            "Overriding variable '***' to '***' for key 'zone_secret'"
        );

        let debug = format!("{variables:?}");
        assert!(!debug.contains("s3cr3t") && !debug.contains("dev"), "{debug}");
        assert!(debug.contains("\"zone_secret\": \"***\""), "{debug}");
        assert!(debug.contains("\"env\": \"***\""), "{debug}");
    }

    #[test]
    fn test_variables_in_domain_at_ip_url() {
        let mut variables = VariablesCompiled::default();
        variables
            .data
            .insert("cert_domain".to_string(), "certs.example.com".into());
        variables
            .data
            .insert("cert_ip".to_string(), "12.3.3.2".into());

        let result = variables
            .apply_variables(
                "https://${cert_domain}@${cert_ip}:8005/api/certificates/v1/private-key?domain=x-fine.online"
                    .to_string(),
            )
            .unwrap();

        assert_eq!(
            result,
            "https://certs.example.com@12.3.3.2:8005/api/certificates/v1/private-key?domain=x-fine.online"
        );
    }
}
