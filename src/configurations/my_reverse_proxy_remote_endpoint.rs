use std::sync::Arc;

use my_ssh::{ssh_settings::OverSshConnectionSettings, SshCredentials};
use rust_extensions::remote_endpoint::RemoteEndpointOwned;

use crate::settings_compiled::SettingsCompiled;

pub const GATEWAY_PREFIX: &str = "gateway:";

#[derive(Debug, Clone)]
pub enum MyReverseProxyRemoteEndpoint {
    Gateway {
        id: Arc<String>,
        remote_host: Arc<RemoteEndpointOwned>,
    },
    OverSsh {
        ssh_credentials: Arc<SshCredentials>,
        remote_host: Arc<RemoteEndpointOwned>,
    },
    Direct {
        remote_host: Arc<RemoteEndpointOwned>,
    },
}

impl MyReverseProxyRemoteEndpoint {
    pub fn kind_as_str(&self) -> &'static str {
        match self {
            MyReverseProxyRemoteEndpoint::Direct { .. } => "direct",
            MyReverseProxyRemoteEndpoint::OverSsh { .. } => "ssh",
            MyReverseProxyRemoteEndpoint::Gateway { .. } => "gateway",
        }
    }

    pub fn get_host(&self) -> Option<&str> {
        match self {
            MyReverseProxyRemoteEndpoint::Gateway { id: _, remote_host } => {
                Some(remote_host.get_host())
            }
            MyReverseProxyRemoteEndpoint::OverSsh {
                ssh_credentials: _,
                remote_host,
            } => Some(remote_host.get_host()),
            MyReverseProxyRemoteEndpoint::Direct { remote_host } => Some(remote_host.get_host()),
        }
    }

    pub fn get_path_and_query(&self) -> &str {
        match self {
            MyReverseProxyRemoteEndpoint::Gateway { id: _, remote_host } => {
                remote_host.get_http_path_and_query().unwrap_or("/")
            }
            MyReverseProxyRemoteEndpoint::OverSsh {
                ssh_credentials: _,
                remote_host,
            } => remote_host.get_http_path_and_query().unwrap_or("/"),
            MyReverseProxyRemoteEndpoint::Direct { remote_host } => {
                remote_host.get_http_path_and_query().unwrap_or("/")
            }
        }
    }
    /// Whether the upstream is a unix socket: a `unix+http://`, `http+unix://` or `unix://` URL,
    /// or - through a gateway, whose far side connects to a socket path it is given - the bare
    /// path of a socket file.
    #[cfg(not(unix))]
    pub fn is_unix_socket(&self) -> bool {
        let is_unix_socket_url = |remote_host: &RemoteEndpointOwned| {
            matches!(
                remote_host.get_scheme(),
                Some(rust_extensions::remote_endpoint::Scheme::UnixSocket)
            )
        };

        match self {
            MyReverseProxyRemoteEndpoint::Gateway { remote_host, .. } => {
                is_unix_socket_url(remote_host) || remote_host.as_str().starts_with('/')
            }
            MyReverseProxyRemoteEndpoint::OverSsh { .. } => false,
            MyReverseProxyRemoteEndpoint::Direct { remote_host } => is_unix_socket_url(remote_host),
        }
    }

    pub async fn try_parse(
        remote_host: &str,
        settings_model: &SettingsCompiled,
    ) -> Result<Self, String> {
        if remote_host.starts_with(GATEWAY_PREFIX) {
            MyReverseProxyRemoteEndpoint::try_parse_gateway_source(remote_host)
        } else {
            // On Windows `C:/www` is a local folder as `C:\www` is. A path behind ssh is never
            // taken for one: a source which starts with `ssh` does not start with a drive.
            let remote_host = super::drive_path_with_backslashes(remote_host);
            let over_ssh_connection = OverSshConnectionSettings::try_parse(remote_host.as_ref());

            if over_ssh_connection.is_none() {
                return Err(format!("Invalid remote host {}", remote_host));
            }

            let over_ssh_connection = crate::scripts::ssh::enrich_with_private_key_or_password(
                over_ssh_connection.unwrap(),
                settings_model,
            )
            .await?;

            over_ssh_connection.try_into()
        }
    }

    pub fn try_parse_gateway_source(src: &str) -> Result<Self, String> {
        let mut src_split = src.split("->");

        let left = src_split.next().unwrap();

        let right = src_split.next();

        if right.is_none() {
            return Err(format!("Invalid gateway source: {}", src));
        }

        let right = right.unwrap();

        let gateway_id = get_gateway_id(left)?;

        let remote_host = RemoteEndpointOwned::try_parse(right.to_string())?;

        Ok(Self::Gateway {
            id: gateway_id.to_string().into(),
            remote_host: remote_host.into(),
        })
    }
}

impl std::fmt::Display for MyReverseProxyRemoteEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MyReverseProxyRemoteEndpoint::Gateway { id, remote_host } => {
                write!(f, "{GATEWAY_PREFIX}{}->{}", id, remote_host.as_str())
            }
            MyReverseProxyRemoteEndpoint::OverSsh {
                ssh_credentials,
                remote_host,
            } => {
                write!(
                    f,
                    "ssh:{}->{}",
                    ssh_credentials.to_string().as_str(),
                    remote_host.as_str()
                )
            }
            MyReverseProxyRemoteEndpoint::Direct { remote_host } => {
                f.write_str(remote_host.as_str())
            }
        }
    }
}

impl TryInto<MyReverseProxyRemoteEndpoint> for OverSshConnectionSettings {
    type Error = String;

    fn try_into(self) -> Result<MyReverseProxyRemoteEndpoint, Self::Error> {
        match self.ssh_credentials {
            Some(ssh_credentials) => Ok(MyReverseProxyRemoteEndpoint::OverSsh {
                ssh_credentials,
                remote_host: RemoteEndpointOwned::try_parse(self.remote_resource_string)?.into(),
            }),
            None => Ok(MyReverseProxyRemoteEndpoint::Direct {
                remote_host: RemoteEndpointOwned::try_parse(self.remote_resource_string)?.into(),
            }),
        }
    }
}

fn get_gateway_id(src: &str) -> Result<&str, String> {
    let index = src.find(":");
    if index.is_none() {
        return Err(format!("Can not extract id from gateway prefix: '{}'", src));
    }

    let index = index.unwrap();

    let result = &src[index + 1..];

    Ok(result)
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    /// `RemoteEndpoint` refuses `C:/www` - a scheme `C` - and reads `C:\www` as a path.
    #[tokio::test]
    async fn a_drive_path_written_with_slashes_is_a_local_folder() {
        let endpoint =
            MyReverseProxyRemoteEndpoint::try_parse("C:/www/site", &SettingsCompiled::default())
                .await
                .unwrap();

        let MyReverseProxyRemoteEndpoint::Direct { remote_host } = &endpoint else {
            panic!("{endpoint}");
        };

        assert_eq!(remote_host.as_str(), r"C:\www\site");
    }
}
