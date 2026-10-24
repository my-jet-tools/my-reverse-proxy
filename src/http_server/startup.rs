use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
};

use mcp_server_middleware::McpMiddleware;
use my_http_server::{
    controllers::swagger::SwaggerMiddleware, MyHttpServer, StaticFilesMiddleware,
};

use crate::mcp::{
    GetAppliedSettingsHandler, GetClientCaEndpointsStatusHandler, GetClientCertificateCaHandler,
    GetDynamicSettingsHandler, GetProxyLogsHandler, GetProxyStateSnapshotHandler,
    GetSettingsHandler, GetSslCertificateHandler, GetSslEndpointsStatusHandler,
    InitClientCertificateCaHandler, InitSslCertificateHandler, LookupPoolHandler,
    ReloadSettingsHandler, SetDynamicSettingsHandler,
};

const DEFAULT_PORT: u16 = 8000;

pub fn start() {
    start_at(control_port_addr(
        crate::app::APP_CTX.http_control_ip,
        crate::app::APP_CTX.http_control_port,
    ));
}

/// The address of the control port: `http_control_ip` and `http_control_port` of the global
/// settings, `0.0.0.0` and 8000 for what is not given.
pub fn control_port_addr(
    http_control_ip: Option<IpAddr>,
    http_control_port: Option<u16>,
) -> SocketAddr {
    let http_port = if let Some(listen_port) = http_control_port {
        listen_port
    } else {
        DEFAULT_PORT
    };

    let http_ip = http_control_ip.unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));

    SocketAddr::new(http_ip, http_port)
}

/// The control port server at the address given.
pub fn start_at(addr: SocketAddr) {
    let mut http_server = MyHttpServer::new(addr);

    let controllers = Arc::new(super::builder::build_controllers());

    let swagger_middleware = SwaggerMiddleware::new(
        controllers.clone(),
        crate::app::APP_NAME,
        crate::app::APP_VERSION,
    );

    http_server.add_middleware(Arc::new(swagger_middleware));

    let mut mcp = McpMiddleware::new(
        "/mcp",
        crate::app::APP_NAME,
        crate::app::APP_VERSION,
        "my-reverse-proxy diagnostic snapshots — pools, locations, and their correlation",
    );
    mcp.register_tool_call(Arc::new(GetProxyStateSnapshotHandler));
    mcp.register_tool_call(Arc::new(LookupPoolHandler));
    mcp.register_tool_call(Arc::new(GetSettingsHandler));
    mcp.register_tool_call(Arc::new(GetAppliedSettingsHandler));
    mcp.register_tool_call(Arc::new(ReloadSettingsHandler));
    mcp.register_tool_call(Arc::new(GetDynamicSettingsHandler));
    mcp.register_tool_call(Arc::new(SetDynamicSettingsHandler));
    mcp.register_tool_call(Arc::new(GetProxyLogsHandler));
    mcp.register_tool_call(Arc::new(GetSslEndpointsStatusHandler));
    mcp.register_tool_call(Arc::new(GetSslCertificateHandler));
    mcp.register_tool_call(Arc::new(InitSslCertificateHandler));
    mcp.register_tool_call(Arc::new(GetClientCaEndpointsStatusHandler));
    mcp.register_tool_call(Arc::new(GetClientCertificateCaHandler));
    mcp.register_tool_call(Arc::new(InitClientCertificateCaHandler));

    http_server.add_middleware(Arc::new(mcp));

    http_server.add_middleware(controllers);

    // Serves the Dioxus SPA out of `./wwwroot`. UI is a separate crate
    // (`ui/`); built artifacts are copied here. Falls back
    // to `index.html` for unknown paths so client-side routing works.
    let static_files = StaticFilesMiddleware::new()
        .add_index_file("index.html")
        .set_not_found_file("index.html".to_string())
        .with_etag();

    http_server.add_middleware(Arc::new(static_files));

    http_server.start(
        crate::app::APP_CTX.states.clone(),
        my_logger::LOGGER.clone(),
    );
}
