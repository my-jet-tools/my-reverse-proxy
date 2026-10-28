use std::{sync::Arc, time::Duration};

use rust_extensions::MyTimer;
use timers::{
    CrlRefresherTimer, EndpointRpsTimer, GatewaySyncCertsTimer, GcConnectionsTimer, GcPoolsTimer,
    IpBlocklistGcTimer, MetricsTimer, PoolSupervisorTimer, ResolveDomainsIpTimer,
    SslCertsRefreshTimer, TrafficTimer,
};

mod app;
mod flows;
//mod http2_executor;

mod configurations;
mod consts;
//mod crl;
mod google_auth;
mod http_client_connectors;
mod http_content_source;
mod http_proxy_pass;
mod http_server;
mod self_signed_cert;
mod settings;
mod settings_compiled;
mod tcp_listener;
mod tcp_utils;

mod scripts;

mod error_templates;
mod h1_proxy_server;
mod h1_utils;
mod http2_client_pool;
mod http_client_pool;
mod ip_db;

mod h1_remote_connection;
mod mcp;
mod metrics;
mod my_http2_client;
mod network_stream;
mod oauth;
mod ssl;
mod tcp_gateway;
mod timers;
mod types;
mod upstream_h1_pool;
mod upstream_h2_pool;
mod upstream_status;
mod utils;

#[cfg(windows)]
mod win_service;

pub fn to_hyper_error(e: std::convert::Infallible) -> String {
    e.to_string()
}

/// Linux and macOS: the proxy in the console, and no command line - the options are Windows-only,
/// see `win_service`.
#[cfg(not(windows))]
#[tokio::main]
async fn main() {
    if let Err(err) = console_main().await {
        eprintln!("{err}");
        std::process::exit(1);
    }
}

/// Windows: the console run, and the proxy as a Windows service.
#[cfg(windows)]
fn main() {
    win_service::main();
}

/// The console run: up, until Ctrl+C or SIGTERM, then down.
async fn console_main() -> Result<(), String> {
    start_proxy()
        .await
        .map_err(|err| format!("Can not start. {err}"))?;

    crate::app::APP_CTX.states.wait_until_shutdown().await;

    stop_proxy().await;

    Ok(())
}

/// Brings the proxy up - the settings, the control port, the endpoints, the timers. Shared by the
/// console run and the Windows service, which differ only in what they wait on afterwards.
async fn start_proxy() -> Result<(), String> {
    // Before the settings are read: without a home directory there is no settings file to read,
    // and the process says why.
    crate::settings::settings_file_path()?;

    my_tls::install_default_crypto_providers();

    // Before anything uses APP_CTX: a settings error ends the startup with an error - printed in
    // the console, a stop of the service - instead of a panic.
    crate::app::build_app_ctx()?;

    crate::http_server::start();

    crate::flows::load_everything_from_settings()
        .await
        .map_err(|err| format!("Failed to load initial settings: {err}"))?;

    let mut my_timer = MyTimer::new(Duration::from_secs(3600), my_logger::LOGGER.clone());

    my_timer.register_timer("CRL Refresh", Arc::new(CrlRefresherTimer));

    my_timer.register_timer("SSL Certs Refresh", Arc::new(SslCertsRefreshTimer));

    my_timer.start();

    let mut metrics_timer = MyTimer::new(Duration::from_secs(1), my_logger::LOGGER.clone());

    metrics_timer.register_timer("Metrics", Arc::new(MetricsTimer));
    metrics_timer.register_timer("EndpointRps", Arc::new(EndpointRpsTimer));
    metrics_timer.register_timer("Traffic", Arc::new(TrafficTimer));

    metrics_timer.start();

    let mut gc_connections_time =
        rust_extensions::MyTimer::new(Duration::from_secs(60), my_logger::LOGGER.clone());

    gc_connections_time.register_timer("GcConnections", Arc::new(GcConnectionsTimer));
    gc_connections_time.register_timer("GatewaySyncCerts", Arc::new(GatewaySyncCertsTimer));
    gc_connections_time.register_timer("IpBlocklistGc", Arc::new(IpBlocklistGcTimer));

    gc_connections_time.start();

    let mut pool_supervisor_timer = rust_extensions::MyTimer::new(
        crate::app::APP_CTX.pool_supervisor_interval,
        my_logger::LOGGER.clone(),
    );

    pool_supervisor_timer.register_timer("PoolSupervisor", Arc::new(PoolSupervisorTimer));

    pool_supervisor_timer.start();

    let mut gc_pools_timer =
        rust_extensions::MyTimer::new(Duration::from_secs(60), my_logger::LOGGER.clone());

    gc_pools_timer.register_timer("GcPools", Arc::new(GcPoolsTimer));

    gc_pools_timer.start();

    // Resolve endpoint domains once at startup so the IP shows up immediately,
    // then keep it fresh on a timer.
    tokio::spawn(crate::timers::resolve_endpoint_domains());

    let mut domains_resolve_timer =
        rust_extensions::MyTimer::new(Duration::from_secs(60), my_logger::LOGGER.clone());

    domains_resolve_timer.register_timer("ResolveDomainsIp", Arc::new(ResolveDomainsIpTimer));

    domains_resolve_timer.start();

    Ok(())
}

/// Takes the proxy down: the listeners stop accepting, and the connections in flight get three
/// seconds before the process ends.
async fn stop_proxy() {
    println!("Shutting down...");

    crate::app::APP_CTX.states.set_shutting_down();

    //    app.ssh_to_http_port_forward_pool.clean_up().await;

    tokio::time::sleep(Duration::from_secs(3)).await;

    println!("Stopped...");
}

fn format_mem(size: usize) -> String {
    if size < 1024 {
        return format!("{}B", size);
    }

    let size = size as f64 / 1024.0;

    if size < 1024.0 {
        return format!("{:.2}KB", size);
    }

    let size = size / 1024.0;

    format!("{:.2}Mb", size)
}
