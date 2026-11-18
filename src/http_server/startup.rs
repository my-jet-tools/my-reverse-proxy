use std::{net::SocketAddr, sync::Arc};

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

/// The control port at the address of the settings: `global_settings.http_control_port` and
/// `http_control_ip`, `127.0.0.1:8000` when they say nothing - and on the unix socket of
/// `global_settings.control_unix_socket` too, when it names one.
pub fn start() {
    start_at(crate::app::APP_CTX.http_control_addr);

    if let Some(unix_socket) = crate::app::APP_CTX.http_control_unix_socket.as_ref() {
        start_at_unix_socket(unix_socket);
    }
}

/// The control port server at the address given.
pub fn start_at(addr: SocketAddr) {
    serve(MyHttpServer::new(addr));
}

/// The control port server on the unix socket given: the same as at its address. A file left
/// at the path by a run before is removed first.
#[cfg(unix)]
pub fn start_at_unix_socket(unix_socket: &str) {
    serve(MyHttpServer::new_as_unix_socket(unix_socket));
}

/// The settings load refuses `control_unix_socket` on a platform without unix sockets, so this is
/// never reached there.
#[cfg(not(unix))]
pub fn start_at_unix_socket(unix_socket: &str) {
    panic!("The control port can not be served on the unix socket {unix_socket}: unix sockets are not supported on this platform");
}

/// Everything the control port serves, put on `http_server`, which is started then.
fn serve(mut http_server: MyHttpServer) {
    // The head of an http/1.1 request, and the first bytes of a connection, within the
    // `header_read_timeout` of the global settings - a slow client is not held for ever.
    http_server.set_header_read_timeout(crate::app::APP_CTX.http_control_header_read_timeout);

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
