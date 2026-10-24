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

pub fn to_hyper_error(e: std::convert::Infallible) -> String {
    e.to_string()
}

#[tokio::main]
async fn main() {
    // First of all, before APP_CTX reads the settings: without a home directory there is no
    // settings file to read, and the process says why and stops rather than panics.
    if let Err(err) = crate::settings::settings_file_path() {
        eprintln!("Can not start. {err}");
        std::process::exit(1);
    }

    my_tls::install_default_crypto_providers();
    crate::http_server::start();

    crate::flows::load_everything_from_settings()
        .await
        .expect("Failed to load initial settings");

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

    crate::app::APP_CTX.states.wait_until_shutdown().await;

    println!("Shutting down...");

    //    app.ssh_to_http_port_forward_pool.clean_up().await;

    tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;

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
