use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use http::Method;
use http_body_util::BodyExt;
use my_http_client::http1::{MyHttpClient, MyHttpRequestBuilder};
use my_settings_reader::flurl::FlUrl;
use my_ssh::{ssh_settings::OverSshConnectionSettings, SshCredentials};
use rust_extensions::remote_endpoint::RemoteEndpoint;

use crate::configurations::LocalFilePath;

pub async fn load_file(
    content_source: &OverSshConnectionSettings,
    connect_timeout: Duration,
) -> Result<Vec<u8>, String> {
    if let Some(scheme) = content_source.get_remote_endpoint().get_scheme() {
        match scheme {
            rust_extensions::remote_endpoint::Scheme::Http => {
                load_from_http_or_https(
                    content_source.get_remote_endpoint(),
                    content_source.ssh_credentials.as_ref(),
                    connect_timeout,
                )
                .await
            }
            rust_extensions::remote_endpoint::Scheme::Https => {
                load_from_http_or_https(
                    content_source.get_remote_endpoint(),
                    content_source.ssh_credentials.as_ref(),
                    connect_timeout,
                )
                .await
            }
            _ => {
                panic!(
                    "File can be loaded from the url: {}",
                    content_source.get_remote_endpoint().as_str()
                );
            }
        }
    } else {
        if let Some(ssh_credentials) = content_source.ssh_credentials.as_ref() {
            return loading_file_from_ssh(ssh_credentials, content_source.get_remote_endpoint())
                .await;
        } else {
            let file_name = LocalFilePath::new(content_source.remote_resource_string.to_string());

            let result = tokio::fs::read(file_name.get_value().as_str())
                .await
                .map_err(|err| {
                    format!(
                        "Error reading file: {:?}, error: {:?}",
                        file_name.get_value().as_str(),
                        err
                    )
                })?;

            Ok(result)
        }
    }
}

async fn load_from_http_or_https<'s>(
    remote_endpoint: RemoteEndpoint<'s>,
    ssh_credentials: Option<&Arc<SshCredentials>>,
    connect_timeout: Duration,
) -> Result<Vec<u8>, String> {
    if let Some(ssh_credentials) = ssh_credentials {
        return load_content_from_http_via_ssh(ssh_credentials, remote_endpoint, connect_timeout)
            .await;
    }

    let fl_url = match split_domain_at_ip(remote_endpoint.as_str())? {
        Some(domain_at_ip) => FlUrl::new(domain_at_ip.url).with_header("Host", domain_at_ip.host),
        None => FlUrl::new(remote_endpoint.as_str()),
    };

    let response = fl_url
        .get()
        .await
        .map_err(|err| format!("Error loading file from HTTP. Error: {:?}", err))?;

    let result = response
        .receive_body()
        .await
        .map_err(|itm| format!("Error loading file from HTTP. Error: {:?}", itm))?;

    Ok(result)
}

/// `https://domain@ip:port/path` - the connection goes straight to `ip:port`, `domain` is never
/// resolved: it becomes the Host header, and FlUrl takes the TLS server name from that header.
struct DomainAtIp {
    url: String,
    host: String,
}

fn split_domain_at_ip(src: &str) -> Result<Option<DomainAtIp>, String> {
    let authority_start = match src.find("://") {
        Some(index) => index + 3,
        None => return Ok(None),
    };

    let authority_end = src[authority_start..]
        .find(|c| matches!(c, '/' | '?' | '#'))
        .map_or(src.len(), |index| authority_start + index);

    let Some((domain, ip_port)) = src[authority_start..authority_end].split_once('@') else {
        return Ok(None);
    };

    let port = match ip_port.parse::<SocketAddr>() {
        Ok(socket_addr) => Some(socket_addr.port()),
        Err(_) if ip_port.parse::<Ipv4Addr>().is_ok() => None,
        Err(_) => {
            return Err(format!(
                "Invalid url {}: '{}' after '@' must be ip or ip:port",
                src, ip_port
            ))
        }
    };

    if domain.is_empty() {
        return Err(format!("Invalid url {}: no domain before '@'", src));
    }

    let host = match port {
        Some(port) => format!("{}:{}", domain, port),
        None => domain.to_string(),
    };

    Ok(Some(DomainAtIp {
        url: format!(
            "{}{}",
            &src[..authority_start],
            &src[authority_start + domain.len() + 1..]
        ),
        host,
    }))
}

async fn loading_file_from_ssh<'s>(
    ssh_credentials: &Arc<SshCredentials>,
    remote_endpoint: RemoteEndpoint<'s>,
) -> Result<Vec<u8>, String> {
    let ssh_session = super::ssh::get_ssh_session(ssh_credentials).await?;

    let result = ssh_session
        .download_remote_file(remote_endpoint.as_str(), Duration::from_secs(5))
        .await;

    if let Err(err) = result {
        return Err(format!(
            "Can not download file from remote resource {}->{}. Error: {:?}",
            ssh_credentials.to_string(),
            remote_endpoint.as_str(),
            err
        ));
    }

    let result = result.unwrap();

    Ok(result)
}

async fn load_content_from_http_via_ssh<'s>(
    ssh_credentials: &Arc<SshCredentials>,
    remote_endpoint: RemoteEndpoint<'s>,
    connect_timeout: Duration,
) -> Result<Vec<u8>, String> {
    use crate::http_client_connectors::HttpOverSshConnector;
    use my_ssh::*;

    let ssh_session = super::ssh::get_ssh_session(ssh_credentials).await?;

    let connector = HttpOverSshConnector {
        ssh_session,
        remote_endpoint: remote_endpoint.to_owned(),
        debug: false,
        connect_timeout,
    };

    let http_client: MyHttpClient<SshAsyncChannel, HttpOverSshConnector> =
        MyHttpClient::new(connector);

    let http_request = MyHttpRequestBuilder::new(Method::GET, remote_endpoint.as_str()).build();

    let response = http_client
        .do_request(&http_request, Duration::from_secs(5))
        .await
        .map_err(|err| format!("{:?}", err))?;

    let response = response.into_response();

    let body = response.into_body();

    let body = body.collect().await.map_err(|err| format!("{:?}", err))?;

    let body = body.to_bytes();

    Ok(body.into())
}

#[cfg(test)]
mod tests {
    use super::split_domain_at_ip;

    #[test]
    fn test_domain_at_ip_port() {
        let result = split_domain_at_ip(
            "https://domain.com@12.3.3.2:8005/api/certificates/v1/private-key?domain=x-fine.online",
        )
        .unwrap()
        .unwrap();

        assert_eq!(
            result.url,
            "https://12.3.3.2:8005/api/certificates/v1/private-key?domain=x-fine.online"
        );
        assert_eq!(result.host, "domain.com:8005");
    }

    #[test]
    fn test_domain_at_ip_without_port() {
        let result = split_domain_at_ip("https://domain.com@12.3.3.2/cert.pem")
            .unwrap()
            .unwrap();

        assert_eq!(result.url, "https://12.3.3.2/cert.pem");
        assert_eq!(result.host, "domain.com");
    }

    #[test]
    fn test_domain_at_ipv6_port() {
        let result = split_domain_at_ip("https://domain.com@[::1]:8005/cert.pem")
            .unwrap()
            .unwrap();

        assert_eq!(result.url, "https://[::1]:8005/cert.pem");
        assert_eq!(result.host, "domain.com:8005");
    }

    #[test]
    fn test_url_without_domain_at_ip() {
        assert!(split_domain_at_ip("https://domain.com:8005/cert.pem")
            .unwrap()
            .is_none());

        assert!(
            split_domain_at_ip("https://domain.com:8005/private-key?email=me@domain.com")
                .unwrap()
                .is_none()
        );

        assert!(split_domain_at_ip("https://domain.com?email=me@domain.com")
            .unwrap()
            .is_none());
    }

    #[test]
    fn test_domain_at_not_ip() {
        assert!(split_domain_at_ip("https://domain.com@other.com:8005/cert.pem").is_err());
        assert!(split_domain_at_ip("https://@12.3.3.2:8005/cert.pem").is_err());
    }
}
