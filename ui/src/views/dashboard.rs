use std::time::Duration;

use dioxus::prelude::*;
use dioxus_utils::{js::sleep, DataState, RenderState};

use crate::{
    api,
    models::{
        CurrentConfigurationModel, GatewayClientStatusModel, GatewayConnectionModel,
        GatewayServerStatusModel, HttpEndpointInfoModel, HttpProxyPassLocationModel,
        PortConfigurationModel, SslCertificateInfoModel,
    },
    views::{
        ClientCertDialog, ClientCertDialogRequest, LogScope, LogsDialog, LogsDialogRequest,
        SslCertDialog, SslCertDialogRequest,
    },
};

/// The dialogs the dashboard can open. `Signal` is `Copy`, so this travels through the render
/// helpers by value instead of one parameter per dialog. `None` in a signal means closed.
#[derive(Clone, Copy)]
struct DashboardDialogs {
    logs: Signal<Option<LogsDialogRequest>>,
    ssl_cert: Signal<Option<SslCertDialogRequest>>,
    client_cert: Signal<Option<ClientCertDialogRequest>>,
}

const REFRESH_INTERVAL: Duration = Duration::from_secs(1);

#[component]
pub fn Dashboard() -> Element {
    let mut state = use_signal(DataState::<CurrentConfigurationModel>::new);

    // Start a single background poll loop on mount. Re-renders driven by
    // `state.write()` won't restart it.
    use_hook(|| {
        spawn(async move {
            loop {
                match api::get_current_configuration().await {
                    Ok(data) => state.write().set_value(data),
                    Err(err) => state.write().set_error(err),
                }
                sleep(REFRESH_INTERVAL).await;
            }
        });
    });

    let dialogs = DashboardDialogs {
        logs: use_signal(|| Option::<LogsDialogRequest>::None),
        ssl_cert: use_signal(|| Option::<SslCertDialogRequest>::None),
        client_cert: use_signal(|| Option::<ClientCertDialogRequest>::None),
    };

    let state_ra = state.read();

    let content = match state_ra.as_ref() {
        RenderState::None | RenderState::Loading => {
            rsx! { div { class: "loading", "Loading configuration..." } }
        }
        RenderState::Error(err) => rsx! {
            div { class: "error",
                h3 { "Failed to load configuration" }
                pre { "{err}" }
            }
        },
        RenderState::Loaded(cfg) => render_dashboard(cfg, dialogs),
    };

    let open_logs = dialogs.logs.read().clone();
    let open_ssl_cert = dialogs.ssl_cert.read().clone();
    let open_client_cert = dialogs.client_cert.read().clone();

    rsx! {
        {content}
        if let Some(request) = open_logs {
            LogsDialog { request, dialog: dialogs.logs }
        }
        if let Some(request) = open_ssl_cert {
            SslCertDialog { request, dialog: dialogs.ssl_cert }
        }
        if let Some(request) = open_client_cert {
            ClientCertDialog { request, dialog: dialogs.client_cert }
        }
    }
}

fn render_dashboard(cfg: &CurrentConfigurationModel, dialogs: DashboardDialogs) -> Element {
    rsx! {
        div { class: "dashboard",
            h2 { "Reverse Proxy" }
            for port in &cfg.ports {
                {render_port(port, dialogs)}
            }
            if let Some(server) = cfg.gateway_server.as_ref() {
                {render_gateway_server(server)}
            }
            if !cfg.gateway_clients.is_empty() {
                {render_gateway_clients(&cfg.gateway_clients)}
            }
            if !cfg.ip_lists.is_empty() {
                {render_ip_lists(cfg)}
            }
            if !cfg.ssl_certs.is_empty() {
                {render_ssl_certs(&cfg.ssl_certs)}
            }
            if !cfg.errors.is_empty() {
                section { class: "port",
                    div { class: "port-header",
                        span { class: "label", "Errors" }
                    }
                    div { class: "endpoints",
                        ul {
                            for (host, err) in &cfg.errors {
                                li { b { "{host}" } " — " span { "{err}" } }
                            }
                        }
                    }
                }
            }
        }
    }
}

fn render_ssl_certs(certs: &[SslCertificateInfoModel]) -> Element {
    rsx! {
        section { class: "port",
            div { class: "port-header",
                span { class: "label", "SSL certificates" }
                span { class: "number", "{certs.len()}" }
            }
            div { class: "locations-wrap ssl-table-wrap",
                table { class: "locations",
                    thead {
                        tr {
                            th { "Cert ID" }
                            th { "Days left" }
                            th { "Expires at" }
                        }
                    }
                    tbody {
                        for c in certs {
                            {render_ssl_cert(c)}
                        }
                    }
                }
            }
        }
    }
}

fn render_ssl_cert(c: &SslCertificateInfoModel) -> Element {
    let pill_class = if c.days_left < 7 {
        "days-left critical"
    } else if c.days_left < 30 {
        "days-left warn"
    } else {
        "days-left ok"
    };

    rsx! {
        tr {
            td { class: "id-string", "{c.id}" }
            td {
                span { class: "{pill_class}", "{c.days_left}" }
            }
            td { class: "id-string", "{c.expires_at}" }
        }
    }
}

fn render_gateway_server(server: &GatewayServerStatusModel) -> Element {
    rsx! {
        section { class: "port",
            div { class: "port-header",
                span { class: "label", "Gateway Server" }
                span { class: "number", "{server.connections.len()}" }
                {
                    let conn_class = if server.connections.is_empty() {
                        "conn-count"
                    } else {
                        "conn-count active"
                    };
                    rsx! {
                        span { class: "{conn_class}",
                            span { class: "label", "Clients" }
                            span { class: "value", "{server.connections.len()}" }
                        }
                    }
                }
            }
            if server.connections.is_empty() {
                div { class: "endpoints",
                    div { class: "gateway-empty", "No gateway clients connected" }
                }
            } else {
                {render_gateway_connections(&server.connections)}
            }
        }
    }
}

fn render_gateway_clients(clients: &[GatewayClientStatusModel]) -> Element {
    rsx! {
        section { class: "port",
            div { class: "port-header",
                span { class: "label", "Gateway Clients" }
                span { class: "number", "{clients.len()}" }
            }
            div { class: "endpoints",
                for client in clients {
                    div { class: "endpoint",
                        div { class: "endpoint-header",
                            span { class: "host", "{client.name}" }
                            {
                                let conn_class = if client.connections.is_empty() {
                                    "conn-count endpoint-conn"
                                } else {
                                    "conn-count endpoint-conn active"
                                };
                                rsx! {
                                    span { class: "{conn_class}",
                                        span { class: "label", "Conn" }
                                        span { class: "value", "{client.connections.len()}" }
                                    }
                                }
                            }
                        }
                        if client.connections.is_empty() {
                            div { class: "gateway-empty", "Not connected" }
                        } else {
                            {render_gateway_connections(&client.connections)}
                        }
                    }
                }
            }
        }
    }
}

fn render_gateway_connections(connections: &[GatewayConnectionModel]) -> Element {
    rsx! {
        div { class: "locations-wrap",
            table { class: "locations",
                thead {
                    tr {
                        th { "Gateway" }
                        th { "Forward conn" }
                        th { "Proxy conn" }
                        th { "Ping" }
                        th { "In/s" }
                        th { "Out/s" }
                        th { "Incoming forward" }
                        th { "Connected at" }
                    }
                }
                tbody {
                    for conn in connections {
                        {render_gateway_connection(conn)}
                    }
                }
            }
        }
    }
}

fn render_gateway_connection(conn: &GatewayConnectionModel) -> Element {
    let (forward_label, forward_class) = if conn.is_incoming_forward_connection_allowed {
        ("allowed", "type-pill type-http2")
    } else {
        ("blocked", "type-pill type-drop")
    };

    let route_rows = gateway_route_rows(conn);

    let in_per_sec = fmt_bytes_per_sec(conn.in_history.last().copied().unwrap_or(0));
    let out_per_sec = fmt_bytes_per_sec(conn.out_history.last().copied().unwrap_or(0));

    rsx! {
        tr {
            td { class: "id-string", "{conn.name}" }
            td { "{conn.forward_connections}" }
            td { "{conn.proxy_connections}" }
            td { "{conn.ping_time}" }
            td { "{in_per_sec}" }
            td { "{out_per_sec}" }
            td {
                span { class: "{forward_class}", "{forward_label}" }
            }
            td { class: "id-string", "{conn.timestamp}" }
        }
        if !route_rows.is_empty() {
            tr { class: "gateway-routes-row",
                td { colspan: "8",
                    table { class: "locations gateway-routes",
                        thead {
                            tr {
                                th { "Route" }
                                th { "Forward" }
                                th { "Proxy" }
                            }
                        }
                        tbody {
                            for (route, fwd, proxy) in route_rows.iter() {
                                tr {
                                    td { class: "id-string", "{route}" }
                                    td { "{fwd}" }
                                    td { "{proxy}" }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Union of forward/proxy route keys, sorted, as (route, forward_count, proxy_count).
fn gateway_route_rows(conn: &GatewayConnectionModel) -> Vec<(String, usize, usize)> {
    let mut keys: Vec<&String> = conn
        .forward_routes
        .keys()
        .chain(conn.proxy_routes.keys())
        .collect();
    keys.sort();
    keys.dedup();
    keys.into_iter()
        .map(|k| {
            (
                k.clone(),
                conn.forward_routes.get(k).copied().unwrap_or(0),
                conn.proxy_routes.get(k).copied().unwrap_or(0),
            )
        })
        .collect()
}

fn render_ip_lists(cfg: &CurrentConfigurationModel) -> Element {
    rsx! {
        section { class: "port",
            div { class: "port-header",
                span { class: "label", "IP whitelists" }
                span { class: "number", "{cfg.ip_lists.len()}" }
            }
            div { class: "ip-lists",
                for (id, ips) in &cfg.ip_lists {
                    div { class: "ip-list",
                        div { class: "ip-list-header",
                            span { class: "id", "{id}" }
                            span { class: "count", "{ips.len()}" }
                        }
                        if ips.is_empty() {
                            div { class: "empty", "(empty)" }
                        } else {
                            div { class: "ip-entries",
                                for ip in ips {
                                    span { class: "ip-entry", "{ip}" }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

fn render_port(port: &PortConfigurationModel, dialogs: DashboardDialogs) -> Element {
    let port_type_class = format!("type-pill listen-{}", normalize_type(port.r#type.as_str()));

    let port_conn_class = if port.inbound_connections > 0 {
        "conn-count active"
    } else {
        "conn-count"
    };

    let (logs_id, logs_title) = match port.unix_socket.as_ref() {
        Some(socket) => (socket.clone(), format!("Port logs — unix {socket}")),
        None => (port.port.to_string(), format!("Port logs — {}", port.port)),
    };

    rsx! {
        section { class: "port",
            div { class: "port-header",
                if let Some(socket) = port.unix_socket.as_ref() {
                    span { class: "label", "Unix socket" }
                    span { class: "id-string", "{socket}" }
                    span { class: "{port_type_class}", "{port.r#type}" }
                } else {
                    span { class: "label", "Port" }
                    span { class: "number", "{port.port}" }
                    span { class: "{port_type_class}", "{port.r#type}" }
                    span { class: "{port_conn_class}",
                        span { class: "label", "TCP" }
                        span { class: "value", "{port.inbound_connections}" }
                    }
                }
                {render_logs_button(dialogs, logs_title, LogScope::Port(logs_id))}
            }
            div { class: "endpoints",
                for endpoint in &port.endpoints {
                    {render_endpoint(endpoint, dialogs)}
                }
            }
        }
    }
}

/// A small "logs" button that opens the in-memory logs dialog for a given scope.
fn render_logs_button(dialogs: DashboardDialogs, title: String, scope: LogScope) -> Element {
    let mut logs = dialogs.logs;

    rsx! {
        button {
            class: "logs-btn",
            onclick: move |_| logs.set(Some(LogsDialogRequest { title: title.clone(), scope: scope.clone() })),
            "logs"
        }
    }
}

/// The "SSL cert not loaded" badge. It is a button: clicking it opens the dialog where the
/// certificate and the private key are pasted and uploaded for this endpoint's cert id.
fn render_cert_missing_badge(
    endpoint: &HttpEndpointInfoModel,
    dialogs: DashboardDialogs,
) -> Element {
    let mut ssl_cert = dialogs.ssl_cert;

    // `ssl_cert_missing` is only raised for an endpoint that references a cert id, so the
    // fallback here is defensive.
    let request = SslCertDialogRequest {
        cert_id: endpoint.ssl_cert_id.clone().unwrap_or_default(),
        endpoint_host: endpoint.host.clone(),
    };

    rsx! {
        button {
            class: "cert-missing-badge",
            title: "SSL certificate is not loaded — this endpoint listens but every TLS connection is cut until the certificate is uploaded. Click to paste the certificate and the private key.",
            onclick: move |_| ssl_cert.set(Some(request.clone())),
            "⚠ SSL cert not loaded"
        }
    }
}

/// The "Client cert CA not loaded" badge. It is a button: clicking it opens the dialog where
/// the CA (and optionally its revocation list) is pasted and uploaded for this endpoint's
/// client-certificate id.
fn render_client_ca_missing_badge(
    endpoint: &HttpEndpointInfoModel,
    dialogs: DashboardDialogs,
) -> Element {
    let mut client_cert = dialogs.client_cert;

    // `client_cert_missing` is only raised for an endpoint that references a ca id, so the
    // fallback here is defensive.
    let request = ClientCertDialogRequest {
        ca_id: endpoint.client_cert_id.clone().unwrap_or_default(),
        endpoint_host: endpoint.host.clone(),
    };

    rsx! {
        button {
            class: "cert-missing-badge",
            title: "Client certificate CA is not loaded — this endpoint listens but every TLS connection is cut until the CA is uploaded. Click to paste the CA certificate.",
            onclick: move |_| client_cert.set(Some(request.clone())),
            "⚠ Client cert CA not loaded"
        }
    }
}

#[derive(Clone)]
enum DebugTarget {
    Endpoint(String),
    Location(i64),
}

/// Runtime debug toggle: flips the endpoint/location debug flag on the server.
/// The dashboard polls every second, so the rendered state refreshes on its own.
fn render_debug_toggle(target: DebugTarget, enabled: bool) -> Element {
    let class = if enabled {
        "debug-toggle on"
    } else {
        "debug-toggle"
    };
    rsx! {
        button {
            class: "{class}",
            title: "Toggle debug logging",
            onclick: move |_| {
                let target = target.clone();
                spawn(async move {
                    let _ = match target {
                        DebugTarget::Endpoint(id) => crate::api::set_endpoint_debug(&id, !enabled).await,
                        DebugTarget::Location(id) => crate::api::set_location_debug(id, !enabled).await,
                    };
                });
            },
            if enabled { "debug: on" } else { "debug: off" }
        }
    }
}

fn render_endpoint(endpoint: &HttpEndpointInfoModel, dialogs: DashboardDialogs) -> Element {
    let listen_type_class = format!(
        "type-pill listen-{}",
        normalize_type(endpoint.r#type.as_str())
    );

    let has_meta = endpoint.cloudflare
        || endpoint.ssl_cert_id.is_some()
        || endpoint.client_cert_id.is_some()
        || endpoint.g_auth.is_some()
        || endpoint.allowed_user_list_id.is_some()
        || !endpoint.request_with_header_only.is_empty()
        || endpoint.api_keys_auth.is_some()
        || endpoint.ip_list.is_some()
        || endpoint.country_list.is_some();

    let (cloudflare_chip_class, cloudflare_title) = if endpoint.cloudflare_ranges_missing {
        (
            "meta-chip cloudflare missing",
            "cloudflare: true — but the networks of Cloudflare are not read yet (api.cloudflare.com/client/v4/ips), so the endpoint takes no connection until they are",
        )
    } else {
        (
            "meta-chip cloudflare",
            "cloudflare: true — only Cloudflare may connect; the client of a request is its CF-Connecting-IP. Any other connection is closed without a response and written to the cloudflare-deviations journal",
        )
    };

    let ssl_chip_class = if endpoint.ssl_cert_missing {
        "meta-chip ssl missing"
    } else {
        "meta-chip ssl"
    };

    let client_cert_chip_class = if endpoint.client_cert_missing {
        "meta-chip auth client missing"
    } else {
        "meta-chip auth client"
    };

    rsx! {
        div { class: "endpoint",
            div { class: "endpoint-header",
                span { class: "{listen_type_class}", "{endpoint.r#type}" }
                span { class: "host", "{endpoint.host}" }
                if let Some(ip) = endpoint.resolved_ip.as_ref() {
                    span { class: "resolved-ip", title: "Resolved IP", "({ip})" }
                }
                if endpoint.ssl_cert_missing {
                    {render_cert_missing_badge(endpoint, dialogs)}
                }
                if endpoint.client_cert_missing {
                    {render_client_ca_missing_badge(endpoint, dialogs)}
                }
                {render_debug_toggle(DebugTarget::Endpoint(endpoint.host.clone()), endpoint.debug)}
                {
                    let endpoint_conn_class = if endpoint.inbound_connections > 0 {
                        "conn-count endpoint-conn active"
                    } else {
                        "conn-count endpoint-conn"
                    };
                    rsx! {
                        span { class: "{endpoint_conn_class}",
                            span { class: "label", "TCP" }
                            span { class: "value", "{endpoint.inbound_connections}" }
                        }
                    }
                }
                {render_logs_button(dialogs, format!("Endpoint logs — {}", endpoint.host), LogScope::Endpoint(endpoint.host.clone()))}
            }
            if has_meta {
                div { class: "endpoint-meta",
                    if endpoint.cloudflare {
                        span { class: "{cloudflare_chip_class}", title: "{cloudflare_title}",
                            span { class: "label", "Cloudflare" }
                            span { class: "value", "only" }
                            if endpoint.cloudflare_ranges_missing {
                                span { class: "value state", "ranges not loaded" }
                            }
                        }
                    }
                    if let Some(ssl) = endpoint.ssl_cert_id.as_ref() {
                        span { class: "{ssl_chip_class}",
                            span { class: "label", "SSL" }
                            span { class: "value", "{ssl}" }
                            if endpoint.ssl_cert_missing {
                                span { class: "value state", "not loaded" }
                            }
                        }
                    }
                    if let Some(client) = endpoint.client_cert_id.as_ref() {
                        span { class: "{client_cert_chip_class}",
                            span { class: "label", "Client-Cert" }
                            span { class: "value", "{client}" }
                            if endpoint.client_cert_missing {
                                span { class: "value state", "not loaded" }
                            }
                            if endpoint.client_cert_unlimited_expiration {
                                span {
                                    class: "value state unlimited",
                                    title: "unlimited_expiration: client certificates signed by this CA are accepted however old they are",
                                    "expiry not enforced"
                                }
                            }
                        }
                    }
                    if let Some(auth) = endpoint.g_auth.as_ref() {
                        span { class: "meta-chip auth google",
                            span { class: "label", "Google-Auth" }
                            span { class: "value", "{auth}" }
                        }
                    }
                    if let Some(users) = endpoint.allowed_user_list_id.as_ref() {
                        span { class: "meta-chip auth users",
                            span { class: "label", "Users" }
                            span { class: "value", "{users}" }
                        }
                    }
                    if !endpoint.request_with_header_only.is_empty() {
                        span {
                            class: "meta-chip key",
                            title: "request_with_header_only: every request has to come with these headers, each with its secret value — a request without them is closed without a response. The values are never shown",
                            span { class: "label", "Header-Key" }
                            for name in endpoint.request_with_header_only.iter() {
                                span { class: "value", "{name}: ***" }
                            }
                        }
                    }
                    if let Some(keys) = endpoint.api_keys_auth.as_ref() {
                        span {
                            class: "meta-chip key",
                            title: "api_keys_auth: every location requires a key of the set '{keys}' in X-Api-Key, unless the location names its own set or none",
                            span { class: "label", "API-Key" }
                            span { class: "value", "{keys}" }
                        }
                    }
                    if let Some(ip) = endpoint.ip_list.as_ref() {
                        span {
                            class: "meta-chip ip",
                            title: "whitelisted_ip: only addresses of the list '{ip}' are let in",
                            span { class: "label", "IP-Whitelist" }
                            span { class: "value", "{ip}" }
                        }
                    }
                    if let Some(country) = endpoint.country_list.as_ref() {
                        {render_country_chip(country, &endpoint.country_list_countries)}
                    }
                }
            }
            div { class: "locations-wrap",
                table { class: "locations",
                    thead {
                        tr {
                            th { "Path" }
                            th { "Type" }
                            th { "Upstream" }
                            th { "Access" }
                            th { "Loc id" }
                            th { "Pool" }
                            th { "id_string" }
                            th { "Debug / Logs" }
                        }
                    }
                    tbody {
                        for loc in &endpoint.locations {
                            {render_location(loc, endpoint.api_keys_auth.as_deref(), dialogs)}
                        }
                    }
                }
            }
        }
    }
}

/// `whitelisted_country` chip: the id of the list and the countries it lets in.
fn render_country_chip(id: &str, countries: &[String]) -> Element {
    let title = format!(
        "whitelisted_country: only clients from the countries of the list '{id}' are let in — {}",
        countries_description(countries)
    );

    rsx! {
        span { class: "meta-chip country", title: "{title}",
            span { class: "label", "Country-Whitelist" }
            span { class: "value", "{id}" }
            span { class: "value state", "{countries_label(countries)}" }
        }
    }
}

/// The countries of a list, short: a long list is cut, the whole of it is in the title.
fn countries_label(countries: &[String]) -> String {
    const SHOWN: usize = 6;

    match countries {
        [] => "nobody".to_string(),
        [everybody] if everybody == "*" => "everybody".to_string(),
        _ if countries.len() > SHOWN => format!(
            "{} +{}",
            countries[..SHOWN].join(", "),
            countries.len() - SHOWN
        ),
        _ => countries.join(", "),
    }
}

fn countries_description(countries: &[String]) -> String {
    match countries {
        [] => "the list is empty or not declared, so nobody is let in".to_string(),
        [everybody] if everybody == "*" => "the list has *, so every client is let in".to_string(),
        _ => countries.join(", "),
    }
}

/// What guards a location by itself: its own `whitelisted_ip` / `whitelisted_country` (applied on
/// top of the endpoint's lists), and the API key set it requires — its own, the endpoint's
/// (dimmed), or `none` which opened it although the endpoint requires a key.
fn render_location_access(
    loc: &HttpProxyPassLocationModel,
    endpoint_api_keys: Option<&str>,
) -> Element {
    let api_key = match (loc.api_keys_auth.as_deref(), endpoint_api_keys) {
        (Some(keys), Some(endpoint_keys)) if keys == endpoint_keys => Some((
            "meta-chip key inherited",
            format!("api_keys_auth of the endpoint: a key of the set '{keys}' is required in X-Api-Key"),
            keys.to_string(),
        )),
        (Some(keys), _) => Some((
            "meta-chip key",
            format!("api_keys_auth of the location: a key of the set '{keys}' is required in X-Api-Key"),
            keys.to_string(),
        )),
        (None, Some(endpoint_keys)) => Some((
            "meta-chip key open",
            format!("api_keys_auth: none — this location is open, although the endpoint requires a key of the set '{endpoint_keys}'"),
            "none".to_string(),
        )),
        (None, None) => None,
    };

    let guarded = api_key.is_some() || loc.ip_list.is_some() || loc.country_list.is_some();

    rsx! {
        div { class: "loc-access",
            if let Some((class, title, value)) = api_key {
                span { class: "{class}", title: "{title}",
                    span { class: "label", "API-Key" }
                    span { class: "value", "{value}" }
                }
            }
            if let Some(ip) = loc.ip_list.as_ref() {
                span {
                    class: "meta-chip ip",
                    title: "whitelisted_ip of the location: only addresses of the list '{ip}' are let in (on top of the endpoint's list)",
                    span { class: "label", "IP-Whitelist" }
                    span { class: "value", "{ip}" }
                }
            }
            if let Some(country) = loc.country_list.as_ref() {
                {render_country_chip(country, &loc.country_list_countries)}
            }
            if !guarded {
                span { class: "access-none", "—" }
            }
        }
    }
}

fn render_location(
    loc: &HttpProxyPassLocationModel,
    endpoint_api_keys: Option<&str>,
    dialogs: DashboardDialogs,
) -> Element {
    let pool_label = match (loc.pool_alive, loc.pool_total) {
        (Some(alive), Some(total)) => format!("{alive}/{total}"),
        _ => "—".to_string(),
    };

    let type_class = format!("type-pill type-{}", normalize_type(loc.r#type.as_str()));

    let row_class = match loc.last_status {
        Some(1) => "upstream-ok",
        Some(2) => "upstream-error",
        Some(0) => "upstream-unknown",
        _ => "",
    };

    let logs_title = format!("Location logs — {} ({})", loc.path, loc.location_id);

    rsx! {
        tr { class: "{row_class}",
            td {
                "{loc.path}"
                if loc.strip_path {
                    " "
                    span {
                        class: "type-badge",
                        title: "strip_path: the location path is cut off the request before it goes upstream — /prefix/metrics?x=1 is sent as /metrics?x=1",
                        "strip_path"
                    }
                }
            }
            td {
                span { class: "{type_class}", "{loc.r#type}" }
            }
            td { class: "upstream", "{loc.to}" }
            td { {render_location_access(loc, endpoint_api_keys)} }
            td { "{loc.location_id}" }
            td { "{pool_label}" }
            td { class: "id-string", "{loc.id_string}" }
            td { class: "loc-actions",
                {render_debug_toggle(DebugTarget::Location(loc.location_id), loc.debug)}
                {render_logs_button(dialogs, logs_title, LogScope::Location(loc.location_id))}
            }
        }
    }
}

fn fmt_bytes_per_sec(bytes: usize) -> String {
    let v = bytes as f64;
    if v >= 1_048_576.0 {
        format!("{:.1} MB/s", v / 1_048_576.0)
    } else if v >= 1024.0 {
        format!("{:.1} KB/s", v / 1024.0)
    } else {
        format!("{} B/s", bytes)
    }
}

fn normalize_type(t: &str) -> String {
    // CSS-class friendly slug: lowercase, `+` → `-`.
    t.replace('+', "-").to_ascii_lowercase()
}
