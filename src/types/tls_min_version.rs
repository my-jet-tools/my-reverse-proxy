use my_tls::tokio_rustls::rustls::{
    version::{TLS12, TLS13},
    SupportedProtocolVersion,
};

/// `tls_min_version` of an endpoint: the oldest TLS a client may connect with - nginx's
/// `ssl_protocols`. TLS 1.2 and 1.3 are all the proxy speaks: `1.3` turns 1.2 away.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum TlsMinVersion {
    #[default]
    Tls12,
    Tls13,
}

static FROM_TLS12: [&SupportedProtocolVersion; 2] = [&TLS12, &TLS13];
static FROM_TLS13: [&SupportedProtocolVersion; 1] = [&TLS13];

impl TlsMinVersion {
    /// `tls_min_version` of the endpoint, else of `global_settings`: `1.2` (absent) or `1.3`.
    pub fn resolve(global: Option<&str>, endpoint: Option<&str>) -> Result<Self, String> {
        let (setting, value) = match (endpoint, global) {
            (Some(value), _) => ("tls_min_version", value),
            (None, Some(value)) => ("global_settings.tls_min_version", value),
            (None, None) => return Ok(Self::default()),
        };

        match value.trim() {
            "1.2" => Ok(Self::Tls12),
            "1.3" => Ok(Self::Tls13),
            other => Err(format!("{setting}: '{other}' - it is 1.2 or 1.3")),
        }
    }

    /// The versions of TLS an endpoint speaks.
    pub fn protocol_versions(&self) -> &'static [&'static SupportedProtocolVersion] {
        match self {
            Self::Tls12 => &FROM_TLS12,
            Self::Tls13 => &FROM_TLS13,
        }
    }
}

/// A setting YAML may read as a number - `tls_min_version: 1.3` - taken as the text it was.
pub fn number_or_text<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct Visitor;

    impl serde::de::Visitor<'_> for Visitor {
        type Value = Option<String>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("a number or a text")
        }

        fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Self::Value, E> {
            Ok(Some(value.to_string()))
        }

        fn visit_f64<E: serde::de::Error>(self, value: f64) -> Result<Self::Value, E> {
            Ok(Some(value.to_string()))
        }

        fn visit_u64<E: serde::de::Error>(self, value: u64) -> Result<Self::Value, E> {
            Ok(Some(value.to_string()))
        }

        fn visit_i64<E: serde::de::Error>(self, value: i64) -> Result<Self::Value, E> {
            Ok(Some(value.to_string()))
        }

        fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
            Ok(None)
        }

        fn visit_none<E: serde::de::Error>(self) -> Result<Self::Value, E> {
            Ok(None)
        }
    }

    deserializer.deserialize_any(Visitor)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_endpoint_wins_and_only_1_2_and_1_3_are_versions() {
        assert_eq!(TlsMinVersion::resolve(None, None), Ok(TlsMinVersion::Tls12));
        assert_eq!(
            TlsMinVersion::resolve(Some("1.3"), None),
            Ok(TlsMinVersion::Tls13)
        );
        assert_eq!(
            TlsMinVersion::resolve(Some("1.3"), Some("1.2")),
            Ok(TlsMinVersion::Tls12)
        );

        let err = TlsMinVersion::resolve(None, Some("1.1")).unwrap_err();
        assert!(err.starts_with("tls_min_version: '1.1'"), "{err}");
        assert!(TlsMinVersion::resolve(Some("tls13"), None).is_err());

        assert_eq!(TlsMinVersion::Tls13.protocol_versions().len(), 1);
        assert_eq!(TlsMinVersion::Tls12.protocol_versions().len(), 2);
    }

    #[test]
    fn a_version_reads_from_yaml_as_a_number_or_a_text() {
        #[derive(serde::Deserialize)]
        struct Settings {
            #[serde(default, deserialize_with = "number_or_text")]
            tls_min_version: Option<String>,
        }

        let read = |yaml: &str| {
            serde_yaml::from_str::<Settings>(yaml)
                .unwrap()
                .tls_min_version
        };

        assert_eq!(read("tls_min_version: 1.3"), Some("1.3".to_string()));
        assert_eq!(read("tls_min_version: '1.2'"), Some("1.2".to_string()));
        assert_eq!(read("other: 1"), None);
    }
}
