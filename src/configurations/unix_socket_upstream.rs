use rust_extensions::remote_endpoint::{RemoteEndpointOwned, Scheme};

/// `proxy_pass_to` of a unix socket of this host may name the path of the requests after the
/// socket file, past a `:` - `/var/run/app.sock:/mcp`, `~/sockets/app.sock:/mcp`,
/// `http+unix:///var/run/app.sock:/mcp`. It is the form FlUrl reads (the `UrlBuilder` of
/// my-http-utils) and the one a certificate source on a unix socket is written in: the socket file
/// ends at the first `:` after its start, and the rest is the path and the query.
///
/// Returns the upstream without the path, and the path - `None` when none is written. Anything
/// which is not a unix socket of this host - `http://...`, `ssh:...->...`, `gateway:...->...` -
/// comes back as it is.
pub fn split_unix_socket_path(src: &str) -> Result<(&str, Option<&str>), String> {
    let Some(socket_start) = socket_path_start(src) else {
        return Ok((src, None));
    };

    let Some(colon) = src[socket_start..].find(':') else {
        return Ok((src, None));
    };

    let separator = socket_start + colon;
    let path = &src[separator + 1..];

    if !path.starts_with('/') {
        return Err(format!(
            "'{src}': the path after the socket file has to start with '/': <socket file>:/path"
        ));
    }

    // It goes into the request line as it is written, so it has to be one.
    if let Err(err) = path.parse::<http::uri::PathAndQuery>() {
        return Err(format!(
            "'{src}': '{path}' is not a path of a request: {err}"
        ));
    }

    Ok((&src[..separator], Some(path)))
}

/// Where the socket file starts in `src`, when `src` is a unix socket of this host: a bare path
/// (`/...`, `~...`) at once, a unix socket url (`unix:`, `unix+http:` or `http+unix:`, and a
/// `/`) right after the `:` of its scheme.
fn socket_path_start(src: &str) -> Option<usize> {
    if is_bare_socket_path(src) {
        return Some(0);
    }

    let colon = src.find(':')?;

    if !Scheme::try_parse(&src[..colon])?.is_unix_socket() {
        return None;
    }

    src[colon + 1..].starts_with('/').then_some(colon + 1)
}

/// How an upstream is connected to: as its scheme says - and a bare path, `/var/run/app.sock` or
/// `~/sockets/app.sock`, is the socket file of a unix socket, although `RemoteEndpoint` reads it
/// as a host with no scheme.
pub fn upstream_scheme(remote_host: &RemoteEndpointOwned) -> Option<Scheme> {
    match remote_host.get_scheme() {
        Some(scheme) => Some(scheme),
        None if is_bare_socket_path(remote_host.as_str()) => Some(Scheme::UnixSocket),
        None => None,
    }
}

fn is_bare_socket_path(src: &str) -> bool {
    src.starts_with(['/', '~'])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_path_after_the_socket_file_is_split_off() {
        for (src, socket, path) in [
            ("/var/run/app.sock:/mcp", "/var/run/app.sock", "/mcp"),
            ("~/sockets/app.sock:/mcp", "~/sockets/app.sock", "/mcp"),
            (
                "/var/run/app.sock:/api/v1/mcp?tenant=a",
                "/var/run/app.sock",
                "/api/v1/mcp?tenant=a",
            ),
            (
                "http+unix:///var/run/app.sock:/mcp",
                "http+unix:///var/run/app.sock",
                "/mcp",
            ),
            (
                "unix+http://var/run/app.sock:/mcp",
                "unix+http://var/run/app.sock",
                "/mcp",
            ),
            ("unix:/var/run/app.sock:/", "unix:/var/run/app.sock", "/"),
            (
                "UNIX:///var/run/app.sock:/mcp",
                "UNIX:///var/run/app.sock",
                "/mcp",
            ),
        ] {
            assert_eq!(
                split_unix_socket_path(src).unwrap(),
                (socket, Some(path)),
                "{src}"
            );
        }
    }

    #[test]
    fn a_socket_without_a_path_comes_back_as_it_is() {
        for src in [
            "/var/run/app.sock",
            "~/sockets/app.sock",
            "unix+http:///var/run/app.sock",
            "http+unix://var/run/app.sock",
        ] {
            assert_eq!(split_unix_socket_path(src).unwrap(), (src, None), "{src}");
        }
    }

    /// Their `:` is a scheme's or a port's, and their path is in `RemoteEndpoint`.
    #[test]
    fn what_is_not_a_unix_socket_of_this_host_comes_back_as_it_is() {
        for src in [
            "http://127.0.0.1:8000/mcp",
            "https://mcp.example.com/mcp",
            "127.0.0.1:8000",
            "ssh:root@10.0.0.1:22->http://127.0.0.1:8000/mcp",
            "gateway:gw->/var/run/app.sock:/mcp",
            "unix:8080",
        ] {
            assert_eq!(split_unix_socket_path(src).unwrap(), (src, None), "{src}");
        }
    }

    #[test]
    fn a_path_which_is_not_one_is_refused() {
        for src in [
            "/var/run/app.sock:",
            "/var/run/app.sock:mcp",
            "/var/run/app:1.sock",
            "/var/run/app.sock:/m cp",
            "unix+http:///var/run/app.sock:mcp",
        ] {
            let err = split_unix_socket_path(src).unwrap_err();
            assert!(err.contains(src), "{src}: {err}");
        }
    }

    #[test]
    fn a_bare_path_is_a_unix_socket() {
        let scheme_of =
            |src: &str| upstream_scheme(&RemoteEndpointOwned::try_parse(src.to_string()).unwrap());

        for src in [
            "/var/run/app.sock",
            "~/sockets/app.sock",
            "unix+http:///var/run/app.sock",
        ] {
            assert!(matches!(scheme_of(src), Some(Scheme::UnixSocket)), "{src}");
        }

        assert!(matches!(
            scheme_of("http://host:8000/mcp"),
            Some(Scheme::Http)
        ));
        assert!(scheme_of("host:8000").is_none());
    }
}
