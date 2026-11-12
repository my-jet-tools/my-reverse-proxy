//! The hosts of `dynamic_hosts.url`: how the url is read, and how its hosts are put into the
//! live configuration and served.
//!
//! Nothing on the proxy side is mocked. The hosts of the files are compiled with
//! `scripts::compile_host_configuration` and published into `APP_CTX.current_configuration`, as a
//! reload of the settings does; the dynamic hosts are put next to them by
//! `apply_dynamic_hosts_change`, the function a read of the url applies them with; and the ports
//! are served by the real accept loop. The settings are never read from `~/.my-reverse-proxy`.
//!
//! Every test has hosts of its own, on ports of its own: the live configuration is shared by
//! the tests which run at the same time.

use std::{collections::HashMap, net::SocketAddr, sync::Arc, time::Duration};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

use crate::{
    app::APP_CTX,
    configurations::{EndpointPort, HttpListenPortConfiguration, ListenConfiguration},
    settings::{DynamicHostsModel, DynamicHostsSettings, HostSettings},
    settings_compiled::SettingsCompiled,
};

use super::{apply_dynamic_hosts_change, read_dynamic_hosts};

const TIMEOUT: Duration = Duration::from_secs(10);

// ---------------------------------------------------------------------------------------------
// Reading the url
// ---------------------------------------------------------------------------------------------

/// A server which answers every connection with `response` and closes it.
async fn answer_with(response: String) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let response = response.clone();

            tokio::spawn(async move {
                let _ = read_head(&mut stream).await;
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.shutdown().await;
            });
        }
    });

    port
}

fn url_settings(port: u16) -> DynamicHostsSettings {
    DynamicHostsSettings {
        url: format!("http://127.0.0.1:{port}/hosts"),
        refresh_interval: None,
        request_timeout: Some(2000),
    }
}

fn ok_response(content_type: &str, body: &str) -> String {
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

#[tokio::test]
async fn the_hosts_are_read_from_the_url_in_yaml_and_in_json() {
    let yaml = "hosts:\n  a.example.com:8000:\n    endpoint:\n      type: http\n    locations:\n    - proxy_pass_to: http://127.0.0.1:9000\n";
    let json = r#"{"hosts":{"a.example.com:8000":{"endpoint":{"type":"http"},"locations":[{"proxy_pass_to":"http://127.0.0.1:9000"}]}}}"#;

    for (content_type, body) in [("application/yaml", yaml), ("application/json", json)] {
        let port = answer_with(ok_response(content_type, body)).await;

        let hosts = read_dynamic_hosts(&url_settings(port))
            .await
            .unwrap()
            .unwrap();

        assert_eq!(hosts.len(), 1, "{content_type}");
        assert!(hosts.contains_key("a.example.com:8000"), "{content_type}");
    }
}

/// A `2xx` with a blank body says nothing: it is neither hosts nor a failure, and the caller
/// keeps the hosts it read before.
#[tokio::test]
async fn a_blank_answer_says_nothing() {
    for response in [
        "HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n".to_string(),
        "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n".to_string(),
        ok_response("application/json", ""),
        ok_response("application/yaml", " \r\n"),
    ] {
        let port = answer_with(response.clone()).await;

        let answer = read_dynamic_hosts(&url_settings(port)).await;

        assert!(matches!(answer, Ok(None)), "{response:?}: {answer:?}");
    }
}

/// No hosts are said with hosts which have nothing in them: the ones served before go.
#[tokio::test]
async fn hosts_with_nothing_in_them_are_no_hosts() {
    for response in [
        ok_response("application/yaml", "hosts:\n"),
        ok_response("application/json", r#"{"hosts":{}}"#),
    ] {
        let port = answer_with(response.clone()).await;

        let hosts = read_dynamic_hosts(&url_settings(port))
            .await
            .unwrap()
            .unwrap_or_else(|| panic!("{response:?} is taken for a blank answer"));

        assert!(hosts.is_empty(), "{response:?}");
    }
}

/// None of these is "no hosts": a url which is being restarted, or answers with something else,
/// must not take every dynamic host away. The caller keeps the hosts it read before.
#[tokio::test]
async fn an_answer_which_is_not_the_hosts_is_a_failure() {
    for (response, expected) in [
        (
            "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                .to_string(),
            "503",
        ),
        (
            "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_string(),
            "404",
        ),
        (
            ok_response("text/html", "<html>maintenance</html>"),
            "not the hosts",
        ),
        (
            ok_response("application/yaml", "ssl_certificates: []\n"),
            "not the hosts",
        ),
    ] {
        let port = answer_with(response.clone()).await;

        let err = read_dynamic_hosts(&url_settings(port)).await.unwrap_err();

        assert!(err.contains(expected), "{response:?}: {err}");
    }
}

#[tokio::test]
async fn a_url_which_does_not_answer_fails_within_the_request_timeout() {
    // Accepts, and never answers.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let mut streams = Vec::new();
        while let Ok((stream, _)) = listener.accept().await {
            streams.push(stream);
        }
    });

    let settings = DynamicHostsSettings {
        request_timeout: Some(300),
        ..url_settings(port)
    };

    let started = std::time::Instant::now();
    let result = read_dynamic_hosts(&settings).await;

    assert!(result.is_err());
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "{:?}",
        started.elapsed()
    );

    let closed_port = free_port().await;
    assert!(read_dynamic_hosts(&url_settings(closed_port))
        .await
        .is_err());
}

// ---------------------------------------------------------------------------------------------
// Serving the hosts
// ---------------------------------------------------------------------------------------------

/// A dynamic host comes next to the hosts of the files on their port, and to a port of its own.
/// A connection which was accepted before serves it with its next request; a new one serves it
/// right away. When the url does not give it any more, it is gone, and the host of the files is
/// served by the very endpoint the reload compiled.
#[tokio::test]
async fn a_dynamic_host_is_served_next_to_the_hosts_of_the_files_and_goes() {
    let id = unique_id();
    let static_upstream = start_upstream("static upstream").await;
    let dynamic_upstream = start_upstream("dynamic upstream").await;
    let port = free_port().await;
    let own_port = free_port().await;

    let static_name = format!("static-{id}.localhost");
    let dynamic_name = format!("dynamic-{id}.localhost");
    let own_name = format!("own-{id}.localhost");

    let before = settings_of_files(&[(format!("{static_name}:{port}"), static_upstream)]);
    publish(&before).await;
    serve(port);

    let static_endpoint = http_port_configuration(port).await.endpoints[0].clone();

    let mut accepted_before = connect(port).await;
    assert_eq!(
        request(&mut accepted_before, &static_name).await,
        served_by("static upstream")
    );
    assert_not_served(port, &dynamic_name).await;

    let mut after = before.clone();
    after.set_dynamic_hosts(&hosts(&[
        (format!("{dynamic_name}:{port}"), dynamic_upstream),
        (format!("{own_name}:{own_port}"), dynamic_upstream),
    ]));
    // A port of its own is to be listened on.
    assert!(apply_dynamic_hosts_change(&before, &after).await);
    // `sync_endpoints` starts the listener of a new port - on 0.0.0.0, so here by hand.
    serve(own_port);

    assert_eq!(
        request(&mut accepted_before, &dynamic_name).await,
        served_by("dynamic upstream")
    );
    assert_eq!(
        request(&mut accepted_before, &static_name).await,
        served_by("static upstream")
    );
    assert_eq!(
        request(&mut connect(port).await, &dynamic_name).await,
        served_by("dynamic upstream")
    );
    assert_eq!(
        request(&mut connect(own_port).await, &own_name).await,
        served_by("dynamic upstream")
    );

    let configuration = http_port_configuration(port).await;
    assert_eq!(configuration.endpoints.len(), 2);
    for endpoint in &configuration.endpoints {
        assert_eq!(
            endpoint.dynamic_host,
            endpoint.as_str().starts_with("dynamic-"),
            "{}",
            endpoint.as_str()
        );
    }

    // The url gives no hosts any more.
    let mut gone = after.clone();
    gone.set_dynamic_hosts(&HashMap::new());
    assert!(apply_dynamic_hosts_change(&after, &gone).await);

    assert_eq!(
        request(&mut accepted_before, &static_name).await,
        served_by("static upstream")
    );
    assert_not_served(port, &dynamic_name).await;

    let configuration = http_port_configuration(port).await;
    assert_eq!(configuration.endpoints.len(), 1);
    assert!(Arc::ptr_eq(&configuration.endpoints[0], &static_endpoint));

    assert!(live_configuration(&EndpointPort::Tcp(own_port))
        .await
        .is_none());
}

/// One dynamic host which can not be served keeps neither the others out nor the host of the
/// files it would replace: each refused host is told about under its own id, and the error goes
/// when the host does.
#[tokio::test]
async fn a_dynamic_host_which_can_not_be_served_leaves_the_rest_alone() {
    let id = unique_id();
    let static_upstream = start_upstream("static upstream").await;
    let dynamic_upstream = start_upstream("dynamic upstream").await;
    let port = free_port().await;

    let static_host = format!("static-{id}.localhost:{port}");
    let before = settings_of_files(&[(static_host.clone(), static_upstream)]);
    publish(&before).await;
    serve(port);

    let static_endpoint = http_port_configuration(port).await.endpoints[0].clone();

    let good_host = format!("good-{id}.localhost:{port}");
    let bad_type_host = format!("bad-type-{id}.localhost:{port}");
    let tcp_host = format!("tcp-{id}.localhost:{port}");
    let same_as_static = static_host.to_uppercase();

    let mut dynamic_hosts = hosts(&[
        (good_host.clone(), dynamic_upstream),
        (same_as_static.clone(), dynamic_upstream),
    ]);
    dynamic_hosts.insert(
        bad_type_host.clone(),
        host_settings(
            "no-such-type",
            &format!("http://127.0.0.1:{dynamic_upstream}"),
        ),
    );
    dynamic_hosts.insert(
        tcp_host.clone(),
        host_settings("tcp", &format!("127.0.0.1:{dynamic_upstream}")),
    );

    let mut after = before.clone();
    after.set_dynamic_hosts(&dynamic_hosts);
    // The port was listened on already.
    assert!(!apply_dynamic_hosts_change(&before, &after).await);

    assert_eq!(
        request(&mut connect(port).await, &format!("good-{id}.localhost")).await,
        served_by("dynamic upstream")
    );
    assert_eq!(
        request(&mut connect(port).await, &format!("static-{id}.localhost")).await,
        served_by("static upstream")
    );

    let configuration = http_port_configuration(port).await;
    assert_eq!(configuration.endpoints.len(), 2);
    assert!(Arc::ptr_eq(&configuration.endpoints[0], &static_endpoint));

    let errors = configuration_errors().await;
    assert!(errors.contains_key(&bad_type_host), "{errors:?}");
    assert!(
        errors[&tcp_host].contains("a tcp endpoint takes the port for itself"),
        "{errors:?}"
    );
    // The refusal is not put under the id of the host of the files: it is not that host's error.
    assert!(!errors.contains_key(&same_as_static), "{errors:?}");
    assert!(!errors.contains_key(&static_host), "{errors:?}");
    assert!(after.dynamic_host_errors[&same_as_static]
        .contains("the settings files have a host with this id"));

    // The url gives the good host only.
    let mut fixed = after.clone();
    fixed.set_dynamic_hosts(&hosts(&[(good_host.clone(), dynamic_upstream)]));
    assert!(!apply_dynamic_hosts_change(&after, &fixed).await);

    let errors = configuration_errors().await;
    for host_id in [&bad_type_host, &tcp_host, &same_as_static, &good_host] {
        assert!(!errors.contains_key(host_id), "{host_id}: {errors:?}");
    }
    assert_eq!(
        request(&mut connect(port).await, &format!("good-{id}.localhost")).await,
        served_by("dynamic upstream")
    );
}

/// A read which changes the hosts of one port leaves every other port with its very
/// configuration: the connections there have nothing to pick up.
#[tokio::test]
async fn a_port_whose_hosts_did_not_change_is_not_touched() {
    let id = unique_id();
    let upstream = start_upstream("upstream").await;
    let first_upstream = start_upstream("first upstream").await;
    let second_upstream = start_upstream("second upstream").await;
    let kept_port = free_port().await;
    let changed_port = free_port().await;

    let kept_host = format!("kept-{id}.localhost:{kept_port}");
    let changed_host = format!("changed-{id}.localhost:{changed_port}");

    let before = SettingsCompiled::default();
    let mut first = before.clone();
    first.set_dynamic_hosts(&hosts(&[
        (kept_host.clone(), upstream),
        (changed_host.clone(), first_upstream),
    ]));
    assert!(apply_dynamic_hosts_change(&before, &first).await);
    serve(changed_port);

    let kept = http_port_configuration(kept_port).await;
    let changed = http_port_configuration(changed_port).await;

    assert_eq!(
        request(
            &mut connect(changed_port).await,
            &format!("changed-{id}.localhost")
        )
        .await,
        served_by("first upstream")
    );

    let mut second = first.clone();
    second.set_dynamic_hosts(&hosts(&[
        (kept_host.clone(), upstream),
        (changed_host.clone(), second_upstream),
    ]));
    assert!(!apply_dynamic_hosts_change(&first, &second).await);

    assert!(Arc::ptr_eq(
        &http_port_configuration(kept_port).await,
        &kept
    ));
    assert!(!Arc::ptr_eq(
        &http_port_configuration(changed_port).await,
        &changed
    ));
    assert_eq!(
        request(
            &mut connect(changed_port).await,
            &format!("changed-{id}.localhost")
        )
        .await,
        served_by("second upstream")
    );

    // The same hosts once more: nothing is touched at all.
    let mut third = second.clone();
    third.set_dynamic_hosts(&hosts(&[
        (kept_host, upstream),
        (changed_host, second_upstream),
    ]));
    let changed = http_port_configuration(changed_port).await;
    assert!(!apply_dynamic_hosts_change(&second, &third).await);

    assert!(Arc::ptr_eq(
        &http_port_configuration(changed_port).await,
        &changed
    ));
}

/// The whole way a read of the url goes, from `refresh_dynamic_hosts`: the hosts it answers
/// with are served; while it fails, or answers with a blank body, the ones read before stay;
/// what it does not give any more goes. The only test which uses `APP_CTX.applied_settings` and `APP_CTX.dynamic_hosts`.
#[tokio::test]
async fn the_hosts_of_the_url_are_served_and_follow_what_it_answers() {
    let id = unique_id();
    let static_upstream = start_upstream("static upstream").await;
    let dynamic_upstream = start_upstream("dynamic upstream").await;
    let port = free_port().await;

    // A host of the files on the port: the dynamic one comes next to it, and the listener the
    // test runs stays the port's - nothing is to be started or stopped.
    let static_host = format!("static-{id}.localhost:{port}");
    let dynamic_name = format!("dynamic-{id}.localhost");
    let dynamic_host = format!("{dynamic_name}:{port}");

    let answer = Arc::new(parking_lot::Mutex::new(String::new()));
    let url_port = answer_with_what_is_set(answer.clone()).await;

    let hosts_answer = ok_response(
        "application/yaml",
        &format!(
            "hosts:\n  {dynamic_host}:\n    endpoint:\n      type: http\n    locations:\n    - proxy_pass_to: http://127.0.0.1:{dynamic_upstream}\n"
        ),
    );

    let mut settings = settings_of_files(&[(static_host.clone(), static_upstream)]);
    settings.dynamic_hosts = Some(DynamicHostsSettings {
        refresh_interval: Some(60_000),
        ..url_settings(url_port)
    });
    publish(&settings).await;
    serve(port);
    APP_CTX.applied_settings.store(Some(Arc::new(settings)));

    *answer.lock() = hosts_answer.clone();
    assert_eq!(
        super::refresh_dynamic_hosts().await,
        Some(Duration::from_secs(60))
    );

    assert_eq!(
        request(&mut connect(port).await, &dynamic_name).await,
        served_by("dynamic upstream")
    );
    assert!(APP_CTX
        .applied_settings
        .load_full()
        .unwrap()
        .is_dynamic_host(&dynamic_host));

    // The url is down: the host read before is served.
    *answer.lock() =
        "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            .to_string();
    let configuration = http_port_configuration(port).await;
    super::refresh_dynamic_hosts().await;

    assert!(APP_CTX
        .dynamic_hosts
        .get_last_error()
        .unwrap()
        .contains("503"));
    assert!(Arc::ptr_eq(
        &http_port_configuration(port).await,
        &configuration
    ));
    assert_eq!(
        request(&mut connect(port).await, &dynamic_name).await,
        served_by("dynamic upstream")
    );

    // Up again, with the same hosts: nothing to apply.
    *answer.lock() = hosts_answer;
    super::refresh_dynamic_hosts().await;

    assert!(APP_CTX.dynamic_hosts.get_last_error().is_none());
    assert!(Arc::ptr_eq(
        &http_port_configuration(port).await,
        &configuration
    ));

    // A 200 with a blank body says nothing: the host read before stays, and it is no failure.
    *answer.lock() = ok_response("application/json", "");
    super::refresh_dynamic_hosts().await;

    assert!(APP_CTX.dynamic_hosts.get_last_error().is_none());
    assert!(APP_CTX
        .dynamic_hosts
        .get_hosts(&url_settings(url_port).url)
        .unwrap()
        .contains_key(&dynamic_host));
    assert!(Arc::ptr_eq(
        &http_port_configuration(port).await,
        &configuration
    ));
    assert_eq!(
        request(&mut connect(port).await, &dynamic_name).await,
        served_by("dynamic upstream")
    );

    // The url has no hosts any more.
    *answer.lock() = ok_response("application/yaml", "hosts: {}\n");
    super::refresh_dynamic_hosts().await;

    assert_not_served(port, &dynamic_name).await;
    assert_eq!(
        request(&mut connect(port).await, &format!("static-{id}.localhost")).await,
        served_by("static upstream")
    );
    assert_eq!(http_port_configuration(port).await.endpoints.len(), 1);

    // The settings have no `dynamic_hosts` any more: nothing is read, and nothing is kept.
    let mut settings = APP_CTX
        .applied_settings
        .load_full()
        .unwrap()
        .as_ref()
        .clone();
    settings.dynamic_hosts = None;
    APP_CTX.applied_settings.store(Some(Arc::new(settings)));

    assert_eq!(super::refresh_dynamic_hosts().await, None);
    assert!(APP_CTX
        .dynamic_hosts
        .get_hosts(&url_settings(url_port).url)
        .is_none());
}

/// What a port has already, and a dynamic host to be put on it: where it would take the place
/// of a host of the files - or of the port, for a tcp endpoint - it is refused.
#[tokio::test]
async fn a_dynamic_host_is_put_next_to_what_a_port_has_never_in_its_place() {
    let http = |host_id: &str| {
        (
            host_id.to_string(),
            host_settings("http", "http://127.0.0.1:9000"),
        )
    };
    let tcp = |host_id: &str| (host_id.to_string(), host_settings("tcp", "127.0.0.1:9000"));

    // The hosts compiled on one port, in their order; `dynamic` names the ones of the url.
    async fn port_with(hosts: &[(String, HostSettings)], dynamic: &[&str]) -> ListenConfiguration {
        let settings = SettingsCompiled {
            hosts: hosts.iter().cloned().collect(),
            dynamic_host_ids: dynamic.iter().map(|id| id.to_string()).collect(),
            ..Default::default()
        };

        let mut result = None;
        for (host_id, host_settings) in hosts {
            result = Some(
                crate::scripts::compile_host_configuration(
                    &settings,
                    settings.get_endpoint_host_string(host_id).unwrap(),
                    host_settings,
                    result,
                )
                .await
                .unwrap(),
            );
        }
        result.unwrap()
    }

    let check = |existing: &ListenConfiguration,
                 (host_id, host_settings): (String, HostSettings)| {
        super::check_dynamic_host_fits(
            existing,
            &crate::configurations::EndpointHttpHostString::new(host_id).unwrap(),
            &host_settings,
        )
    };

    let files_http = port_with(&[http("a.localhost:7001")], &[]).await;
    assert!(check(&files_http, http("b.localhost:7001")).is_ok());
    assert!(check(&files_http, http("A.LOCALHOST:7001")).is_err());
    assert!(check(&files_http, tcp("b.localhost:7001")).is_err());

    let files_tcp = port_with(&[tcp("a.localhost:7002")], &[]).await;
    assert!(check(&files_tcp, http("b.localhost:7002")).is_err());
    assert!(check(&files_tcp, tcp("a.localhost:7002")).is_err());

    // The dynamic host served before is the host itself: it is replaced.
    let dynamic_http = port_with(&[http("a.localhost:7003")], &["a.localhost:7003"]).await;
    assert!(check(&dynamic_http, http("a.localhost:7003")).is_ok());
    assert!(check(&dynamic_http, tcp("a.localhost:7003")).is_ok());
    assert!(check(&dynamic_http, tcp("b.localhost:7003")).is_err());

    let dynamic_tcp = port_with(&[tcp("a.localhost:7004")], &["a.localhost:7004"]).await;
    assert!(check(&dynamic_tcp, tcp("a.localhost:7004")).is_ok());
    assert!(check(&dynamic_tcp, http("b.localhost:7004")).is_err());

    let both = port_with(
        &[http("a.localhost:7005"), http("b.localhost:7005")],
        &["b.localhost:7005"],
    )
    .await;
    assert!(check(&both, http("b.localhost:7005")).is_ok());
    assert!(check(&both, http("a.localhost:7005")).is_err());
}

#[test]
fn the_hosts_of_the_files_are_put_on_their_ports_first() {
    let mut settings = SettingsCompiled {
        hosts: hosts(&[
            ("m.localhost:7000".to_string(), 9000),
            ("z.localhost:7000".to_string(), 9000),
        ]),
        ..Default::default()
    };
    settings.set_dynamic_hosts(&hosts(&[
        ("c.localhost:7000".to_string(), 9000),
        ("a.localhost:7000".to_string(), 9000),
        ("b.localhost:7000".to_string(), 9000),
    ]));

    let order: Vec<&str> = settings
        .hosts_in_apply_order()
        .into_iter()
        .map(|(host_id, _)| host_id.as_str())
        .collect();

    let mut files = order[..2].to_vec();
    files.sort();
    assert_eq!(files, ["m.localhost:7000", "z.localhost:7000"]);
    assert_eq!(
        order[2..],
        ["a.localhost:7000", "b.localhost:7000", "c.localhost:7000"]
    );
}

/// A server which answers every connection with what `answer` holds at the time.
async fn answer_with_what_is_set(answer: Arc<parking_lot::Mutex<String>>) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let response = answer.lock().clone();

            tokio::spawn(async move {
                let _ = read_head(&mut stream).await;
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.shutdown().await;
            });
        }
    });

    port
}

// ---------------------------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------------------------

fn unique_id() -> String {
    uuid::Uuid::new_v4().simple().to_string()[..12].to_string()
}

async fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn host_settings(endpoint_type: &str, proxy_pass_to: &str) -> HostSettings {
    let yaml = format!(
        "hosts:\n  'host':\n    endpoint:\n      type: {endpoint_type}\n    locations:\n    - proxy_pass_to: '{proxy_pass_to}'\n"
    );

    DynamicHostsModel::parse(yaml.as_bytes())
        .unwrap()
        .unwrap()
        .hosts
        .remove("host")
        .unwrap()
}

/// `type: http` hosts, each proxied to an upstream on 127.0.0.1.
fn hosts(items: &[(String, u16)]) -> HashMap<String, HostSettings> {
    items
        .iter()
        .map(|(host_id, upstream)| {
            (
                host_id.clone(),
                host_settings("http", &format!("http://127.0.0.1:{upstream}")),
            )
        })
        .collect()
}

fn settings_of_files(items: &[(String, u16)]) -> SettingsCompiled {
    SettingsCompiled {
        hosts: hosts(items),
        ..Default::default()
    }
}

/// What a reload of the settings does with the hosts of the files: each is compiled next to
/// what its port has already, and published into the live configuration.
async fn publish(settings: &SettingsCompiled) {
    for (host_id, host_settings) in &settings.hosts {
        let endpoint_host = settings.get_endpoint_host_string(host_id).unwrap();
        let port = endpoint_host.get_port();
        let existing = live_configuration(&port).await;

        let configuration = crate::scripts::compile_host_configuration(
            settings,
            endpoint_host,
            host_settings,
            existing,
        )
        .await
        .unwrap();

        let EndpointPort::Tcp(port) = port else {
            panic!("{host_id} is not a tcp port");
        };

        APP_CTX
            .current_configuration
            .write(move |config| {
                config.listen_tcp_endpoints.insert(port, configuration);
            })
            .await;
    }
}

async fn live_configuration(port: &EndpointPort) -> Option<ListenConfiguration> {
    APP_CTX
        .current_configuration
        .get(|config| match port {
            EndpointPort::Tcp(port) => config.listen_tcp_endpoints.get(port).cloned(),
            EndpointPort::UnixSocket(path) => {
                config.listen_unix_socket_endpoints.get(path).cloned()
            }
        })
        .await
}

async fn http_port_configuration(port: u16) -> Arc<HttpListenPortConfiguration> {
    match live_configuration(&EndpointPort::Tcp(port)).await {
        Some(ListenConfiguration::Http(config)) => config,
        _ => panic!("port {port} is not an http port"),
    }
}

async fn configuration_errors() -> std::collections::BTreeMap<String, String> {
    APP_CTX
        .current_configuration
        .get(|config| config.error_configurations.clone())
        .await
}

/// The accept loop the proxy runs for a tcp port. `sync_endpoints` starts it on 0.0.0.0; here
/// it is on the loopback.
fn serve(port: u16) {
    crate::tcp_listener::start_listen_tcp_server(SocketAddr::from(([127, 0, 0, 1], port)));
}

/// The accept loop binds its port in a task of its own, so the first attempts may come early.
async fn connect(port: u16) -> TcpStream {
    for _ in 0..500 {
        if let Ok(stream) = TcpStream::connect(("127.0.0.1", port)).await {
            return stream;
        }

        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    panic!("nothing listens on {port}");
}

/// An http/1.1 upstream which answers every request of a connection with `body`.
async fn start_upstream(body: &'static str) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };

            tokio::spawn(async move {
                while read_head(&mut stream).await.is_some() {
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{body}",
                        body.len()
                    );
                    if stream.write_all(response.as_bytes()).await.is_err() {
                        return;
                    }
                }
            });
        }
    });

    port
}

/// The head of a request with no body. `None` once the connection is closed.
async fn read_head(stream: &mut TcpStream) -> Option<Vec<u8>> {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];

    while !head.ends_with(b"\r\n\r\n") {
        match stream.read(&mut byte).await {
            Ok(1) => head.push(byte[0]),
            _ => return None,
        }
    }

    Some(head)
}

fn served_by(body: &str) -> Result<(u16, String), String> {
    Ok((200, body.to_string()))
}

/// `GET /` for `host` over the connection: the status code and the body of the answer.
async fn request(stream: &mut TcpStream, host: &str) -> Result<(u16, String), String> {
    tokio::time::timeout(TIMEOUT, async {
        stream
            .write_all(format!("GET / HTTP/1.1\r\nHost: {host}\r\n\r\n").as_bytes())
            .await
            .map_err(|err| format!("write: {err}"))?;

        let head = read_head(stream)
            .await
            .ok_or_else(|| "the connection is closed".to_string())?;
        let head = String::from_utf8_lossy(&head).to_string();

        let status_code: u16 = head
            .split(' ')
            .nth(1)
            .and_then(|code| code.parse().ok())
            .ok_or_else(|| format!("no status code in {head:?}"))?;

        let content_length = head
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.trim()
                    .eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().ok())?
            })
            .unwrap_or(0);

        let mut body = vec![0u8; content_length];
        stream
            .read_exact(&mut body)
            .await
            .map_err(|err| format!("body: {err}"))?;

        Ok((status_code, String::from_utf8_lossy(&body).to_string()))
    })
    .await
    .map_err(|_| format!("no answer for {host}"))?
}

/// A request for `host` on a new connection is not proxied anywhere.
async fn assert_not_served(port: u16, host: &str) {
    let result = request(&mut connect(port).await, host).await;

    if let Ok((status_code, _)) = &result {
        assert!(*status_code >= 400, "{host} is served: {result:?}");
    }
}
