use std::{sync::Arc, time::Duration};

use rust_extensions::MyTimer;
use timers::{
    CrlRefresherTimer, EndpointRpsTimer, GatewaySyncCertsTimer, GcConnectionsTimer, GcPoolsTimer,
    IpBlocklistGcTimer, MetricsTimer, PoolSupervisorTimer, ResolveDomainsIpTimer,
    SslCertsRefreshTimer, TrafficTimer,
};
use win_service_host::cli::{CliArgs, Mode};

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

/// The name `--install` registers the Windows service under when `--name` is not given; what
/// `--start` and `--uninstall` address.
const DEFAULT_SERVICE_NAME: &str = "my-reverse-proxy";

/// What services.msc shows in the Description column when `--install` is run without
/// `--description`. The service host requires one: a blank line there tells whoever looks at the
/// machine nothing about what the process is.
const DEFAULT_SERVICE_DESCRIPTION: &str =
    "my-reverse-proxy: reverse proxy for http, https, http/2, websocket and tcp endpoints, with \
     ssh and gateway tunnels to the upstreams. The settings file is named in the command line of \
     the service (--settings).";

/// The command line is the one of the win-containers services: no option runs the proxy in the
/// console; `--install`, `--uninstall` and `--start` manage it as a Windows service and exit;
/// `--run-as-service` is what the installed service's command line invokes. `--settings <file>`
/// names the settings file - see `settings::set_settings_file`. Off Windows the service modes
/// answer that they exist on Windows only.
fn main() {
    let args = match win_service_host::cli::parse_args(app::APP_NAME, DEFAULT_SERVICE_NAME) {
        Ok(args) => args,
        Err(usage) => {
            eprintln!("{usage}");
            std::process::exit(2);
        }
    };

    let result = match args.mode {
        Mode::Console => {
            let runtime = tokio::runtime::Runtime::new().expect("Can not build the tokio runtime");
            runtime.block_on(console_main(args.settings.as_deref()))
        }
        Mode::Install => install(&args),
        Mode::Uninstall => win_service_host::uninstall(&args.name),
        Mode::Start => win_service_host::start(&args.name),
        Mode::RunAsService => run_as_service(args),
    };

    if let Err(err) = result {
        eprintln!("{err}");
        std::process::exit(1);
    }
}

/// The console run: up, until Ctrl+C or SIGTERM, then down.
async fn console_main(settings_file: Option<&str>) -> Result<(), String> {
    start_proxy(settings_file)
        .await
        .map_err(|err| format!("Can not start. {err}"))?;

    crate::app::APP_CTX.states.wait_until_shutdown().await;

    stop_proxy().await;

    Ok(())
}

/// `--install`: registers this exe with the Service Control Manager - auto-start at boot,
/// restart-on-failure, a command line with `--run-as-service` and the settings file. The settings
/// file is required here, as `--settings` or as `settings.yaml` next to the exe: a service runs as
/// LocalSystem, whose profile folder holds nobody's `.my-reverse-proxy`, so without a file named
/// at install time the service would start and find no settings.
fn install(args: &CliArgs) -> Result<(), String> {
    let settings_near_exe = win_service_host::cli::resolve_settings_file_near_exe();

    if args.settings.is_none() && settings_near_exe.is_none() {
        return Err(
            "--install needs the settings file: --settings <file>, or a settings.yaml next to the \
             exe. The service runs as LocalSystem, whose home directory is not yours, so the \
             .my-reverse-proxy of your profile would not be read. The folder of the file named is \
             what a leading ~ in the settings stands for."
                .to_string(),
        );
    }

    win_service_host::install(win_service_host::InstallSpec {
        name: &args.name,
        description: args
            .description
            .as_deref()
            .unwrap_or(DEFAULT_SERVICE_DESCRIPTION),
        settings: args.settings.as_deref(),
        settings_near_exe,
    })
}

/// `--run-as-service`: the service host speaks the SCM protocol and calls back in to bring the
/// proxy up, and to take it down when the SCM says stop.
fn run_as_service(args: CliArgs) -> Result<(), String> {
    // A service starts in C:\Windows\System32. The admin ui (wwwroot\) and the IPv6 country
    // database (ip_v6\) are read relative to the working directory, so make it the folder of the
    // exe - where a release puts them, next to it.
    set_current_dir_to_exe_folder()?;

    let settings_file = args.settings;

    win_service_host::run_as_service(
        args.name,
        Box::new(move || {
            Box::pin(async move {
                start_proxy(settings_file.as_deref()).await?;

                let shutdown: win_service_host::ShutdownFn = Box::new(|| Box::pin(stop_proxy()));

                Ok(shutdown)
            })
        }),
    )
}

fn set_current_dir_to_exe_folder() -> Result<(), String> {
    let exe = std::env::current_exe()
        .map_err(|err| format!("Can not determine the path of this exe: {err}"))?;

    let folder = exe
        .parent()
        .ok_or_else(|| format!("The exe {} is not in a folder", exe.display()))?;

    std::env::set_current_dir(folder).map_err(|err| {
        format!(
            "Can not make {} the working directory: {err}",
            folder.display()
        )
    })
}

/// Brings the proxy up - the settings, the control port, the endpoints, the timers. Shared by the
/// console run and the Windows service, which differ only in what they wait on afterwards.
async fn start_proxy(settings_file: Option<&str>) -> Result<(), String> {
    if let Some(settings_file) = settings_file {
        crate::settings::set_settings_file(settings_file)?;
    }

    // Before APP_CTX reads the settings: without a home directory there is no settings file to
    // read, and the process says why and stops rather than panics.
    crate::settings::settings_file_path()?;

    my_tls::install_default_crypto_providers();
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
