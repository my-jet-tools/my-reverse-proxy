use std::{borrow::Cow, sync::Arc, time::Duration};

use flurl::FlUrl;
use http::Method;
use my_http_client::http1::{MyHttpClient, MyHttpRequestBuilder, MyHttpResponse};
use my_ssh::{ssh_settings::OverSshConnectionSettings, SshCredentials};
use rust_extensions::remote_endpoint::RemoteEndpoint;

use crate::configurations::drive_path_with_backslashes;

pub async fn load_file(
    content_source: &OverSshConnectionSettings,
    connect_timeout: Duration,
) -> Result<Vec<u8>, String> {
    // A path behind ssh is one of the remote host, and is sent there as it is.
    let source = if content_source.ssh_credentials.is_some() {
        Cow::Borrowed(content_source.remote_resource_string.as_str())
    } else {
        drive_path_with_backslashes(content_source.remote_resource_string.as_str())
    };

    // Parsed here rather than with `get_remote_endpoint`, which panics on a source it can not
    // parse: a source which is written wrong fails to load like a file which is not there.
    let remote_endpoint = RemoteEndpoint::try_parse(source.as_ref()).map_err(|err| {
        format!(
            "Invalid file source {}: {}",
            content_source.remote_resource_string, err
        )
    })?;

    if let Some(scheme) = remote_endpoint.get_scheme() {
        match scheme {
            rust_extensions::remote_endpoint::Scheme::Http => {
                load_from_http_or_https(
                    remote_endpoint,
                    content_source.ssh_credentials.as_ref(),
                    connect_timeout,
                )
                .await
            }
            rust_extensions::remote_endpoint::Scheme::Https => {
                load_from_http_or_https(
                    remote_endpoint,
                    content_source.ssh_credentials.as_ref(),
                    connect_timeout,
                )
                .await
            }
            _ => Err(format!(
                "File can not be loaded from the url: {}",
                remote_endpoint.as_str()
            )),
        }
    } else {
        if let Some(ssh_credentials) = content_source.ssh_credentials.as_ref() {
            return loading_file_from_ssh(ssh_credentials, remote_endpoint).await;
        } else {
            let file_name = crate::settings::expand_home(source.as_ref())?;

            let result = tokio::fs::read(file_name.as_str()).await.map_err(|err| {
                format!(
                    "Error reading file: {:?}, error: {:?}",
                    file_name.as_str(),
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

    // FlUrl::new never panics: a malformed `https://domain@ip:port/...` source fails the request
    let mut response = FlUrl::new(remote_endpoint.as_str())
        .get()
        .await
        .map_err(|err| format!("Error loading file from HTTP. Error: {:?}", err))?;

    // A file of any size, as before: what is loaded here is named in the settings.
    let result = response
        .get_body()
        .map_err(|itm| format!("Error loading file from HTTP. Error: {:?}", itm))?
        .into_vec(usize::MAX)
        .await
        .map_err(|itm| format!("Error loading file from HTTP. Error: {:?}", itm))?;

    Ok(result)
}

async fn loading_file_from_ssh<'s>(
    ssh_credentials: &Arc<SshCredentials>,
    remote_endpoint: RemoteEndpoint<'s>,
) -> Result<Vec<u8>, String> {
    let ssh_session = super::ssh::get_ssh_session(ssh_credentials).await?;

    let result = super::ssh::download_remote_file(
        &ssh_session,
        remote_endpoint.as_str(),
        Duration::from_secs(5),
    )
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

    let http_request = MyHttpRequestBuilder::new(Method::GET, remote_endpoint.as_str())
        .build()
        .map_err(|err| format!("{:?}", err))?;

    let response = http_client
        .do_request(&http_request, Duration::from_secs(5))
        .await
        .map_err(|err| format!("{:?}", err))?;

    let MyHttpResponse::Response(response) = response else {
        return Err(
            "Error loading file from HTTP via ssh: a websocket upgrade is answered".to_string(),
        );
    };

    // Through the reader of the body, not as collected frames: a frame is the buffer the
    // connection is read into, and with the two of them held a file bigger than both would
    // never be read to its end.
    response
        .into_body()
        .into_vec(usize::MAX)
        .await
        .map_err(|err| format!("{:?}", err))
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use my_ssh::ssh_settings::OverSshConnectionSettings;

    /// A file is loaded from an `https://` source over TLS. Should the FlUrl this file uses ever
    /// be a copy built without TLS - pulled by another dependency from another git url - an
    /// https source fails with `UnsupportedScheme` before a socket is opened.
    #[tokio::test]
    async fn a_file_is_loaded_from_an_https_source_over_tls() {
        let closed_port = {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            listener.local_addr().unwrap().port()
        };

        let source =
            OverSshConnectionSettings::try_parse(&format!("https://127.0.0.1:{closed_port}/x"))
                .unwrap();

        let err = super::load_file(&source, Duration::from_secs(2))
            .await
            .unwrap_err();

        assert!(!err.contains("UnsupportedScheme"), "{err}");
    }

    /// `certs:` is read as a scheme, and there is no such one.
    #[tokio::test]
    async fn a_source_which_can_not_be_parsed_is_an_error_not_a_panic() {
        let source = OverSshConnectionSettings::try_parse("certs:/a.pem").unwrap();

        let err = super::load_file(&source, Duration::from_secs(2))
            .await
            .unwrap_err();

        assert!(err.contains("certs:/a.pem"), "{err}");
    }

    #[tokio::test]
    async fn a_url_which_is_not_http_is_an_error_not_a_panic() {
        let source = OverSshConnectionSettings::try_parse("ws://127.0.0.1/a.pem").unwrap();

        let err = super::load_file(&source, Duration::from_secs(2))
            .await
            .unwrap_err();

        assert!(err.contains("ws://127.0.0.1/a.pem"), "{err}");
    }

    /// `RemoteEndpoint` refuses `C:/...` - a scheme `C` - and reads `C:\...` as a path.
    #[cfg(windows)]
    #[tokio::test]
    async fn a_drive_path_written_with_slashes_is_a_local_file() {
        let file = std::env::temp_dir().join(format!(
            "my-reverse-proxy-load-file-{}.pem",
            std::process::id()
        ));
        std::fs::write(&file, b"content").unwrap();

        let source = file.to_str().unwrap().replace('\\', "/");
        let source = OverSshConnectionSettings::try_parse(&source).unwrap();
        let result = super::load_file(&source, Duration::from_secs(2)).await;

        std::fs::remove_file(&file).unwrap();
        assert_eq!(result.unwrap(), b"content");
    }
}
