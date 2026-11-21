use std::time::Duration;

pub const DEFAULT_HTTP_REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

pub const DEFAULT_HTTP_CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Pause of an accept loop after a failed `accept`. It fails when the process is out of file
/// descriptors (`EMFILE`), and retrying at once would only spin a core on the same error and
/// flood the log with it.
pub const ACCEPT_ERROR_DELAY: Duration = Duration::from_millis(100);

// Transport-level idle read/write timeouts, applied to every byte-pump path
// (H1 request/response transfer, MCP tunnel, TCP port-forward). Endpoint-scoped
// and overridable via the timeout cascade (global → endpoint). The read timeout
// doubles as dead-connection detection: if the peer drops, the pump unblocks
// after this long. 3 minutes balances that against legitimately-idle sessions
// (e.g. an MCP client that only speaks when it issues a request).
pub const DEFAULT_READ_TIMEOUT: Duration = Duration::from_secs(60 * 3);
pub const DEFAULT_WRITE_TIMEOUT: Duration = Duration::from_secs(30);

// Slow-client protection of the http/https endpoints (`header_read_timeout`,
// `tls_handshake_timeout`, `h2_keep_alive_*` in the timeout cascade, global → endpoint).
//
// The whole head of a request has to arrive within this - counted from the moment the
// connection waits for that request with no response of its own still going out (so the
// wait for the next request of a keep-alive connection counts too), or from its first byte.
// `read_timeout` alone would let a client that sends one byte a minute hold a connection
// forever (slowloris).
pub const DEFAULT_HEADER_READ_TIMEOUT: Duration = Duration::from_secs(30);
// The TLS handshake, from the accepted connection to the finished handshake - the ClientHello
// included, so a client that opens a connection and sends nothing is cut by it.
pub const DEFAULT_TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
// h2 PINGs to the clients of http2/https2 endpoints: a connection whose client stopped
// answering is closed instead of being held until TCP itself gives up on it.
pub const DEFAULT_CLIENT_H2_KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(30);
pub const DEFAULT_CLIENT_H2_KEEP_ALIVE_TIMEOUT: Duration = Duration::from_secs(20);
// An h2 connection with no request on it for this long is closed with a GOAWAY - nginx's
// `keepalive_timeout`. A browser opens a new one when it needs it.
pub const DEFAULT_CLIENT_H2_IDLE_TIMEOUT: Duration = Duration::from_secs(180);
pub const DEFAULT_MCP_BUFFER_SIZE: usize = 512 * 1024;

// Request bodies the proxy holds whole in memory before it sends them on (see
// `crate::types::BufferedBodyLimits`).
//
// One body: `max_buffered_request_body` (global → endpoint). The upload limit of the Free and Pro
// plans of Cloudflare: what passes Cloudflare passes here.
pub const DEFAULT_MAX_BUFFERED_REQUEST_BODY: usize = 100 * 1024 * 1024;
// All of them at once, the endpoints together: `max_buffered_request_bodies_total` (global).
pub const DEFAULT_MAX_BUFFERED_REQUEST_BODIES_TOTAL: usize = 512 * 1024 * 1024;

// The limits of one client connection (see `crate::types::ConnectionSettings`), nginx-like.
//
// Requests one connection serves before it is closed: nginx's `keepalive_requests`.
pub const DEFAULT_MAX_REQUESTS_PER_CONNECTION: u32 = 1000;
// The head of an http/1.1 request. nginx allows about 32 KB; cookies of some apps are large.
pub const DEFAULT_MAX_REQUEST_HEAD_SIZE: usize = 64 * 1024;
// Requests open at once on one h2 connection: nginx's `http2_max_concurrent_streams`.
pub const DEFAULT_H2_MAX_CONCURRENT_STREAMS: u32 = 128;
// The decoded headers of one h2 request: the default of hyper.
pub const DEFAULT_H2_MAX_HEADER_LIST_SIZE: u32 = 16 * 1024;

// Client connections held at once (see `crate::app::ConnectionLimits`). `max_connections` is half
// the open files limit of the process; these are its floor, and its value where the limit can not
// be read.
#[cfg(any(unix, test))]
pub const MIN_DEFAULT_MAX_CONNECTIONS: usize = 256;
pub const DEFAULT_MAX_CONNECTIONS_WITHOUT_RLIMIT: usize = 10_000;
// From one address: generous enough for an office behind one NAT address, and far below what a
// flood of connections from one address takes.
pub const DEFAULT_MAX_CONNECTIONS_PER_IP: usize = 1000;

// `access_log`: the file is turned over past this size, and so many turned-over files are kept.
pub const DEFAULT_ACCESS_LOG_MAX_SIZE: usize = 100 * 1024 * 1024;
pub const DEFAULT_ACCESS_LOG_FILES: u32 = 5;

// H1/H2 upstream pool defaults (used when not overridden in the location config).
pub const DEFAULT_POOL_SIZE: u8 = 5;
// How long a connection is considered "hot" after its last successful use —
// within this window the supervisor skips the liveness probe.
pub const DEFAULT_POOL_HOT_WINDOW: Duration = Duration::from_secs(3);
// Per-probe timeout for the supervisor's liveness ping.
pub const DEFAULT_POOL_PING_TIMEOUT: Duration = Duration::from_secs(1);
// How often the (single, global) supervisor sweeps every pool.
pub const DEFAULT_POOL_SUPERVISOR_INTERVAL: Duration = Duration::from_secs(10);

/// Reads of a url of `real_time_configurations` which fail in a row before the ip lists it gave
/// are emptied: from then on they let nobody in, until the url answers again. Its hosts and keys
/// stay as they were.
pub const FAILED_READS_BEFORE_IP_LISTS_ARE_EMPTIED: u32 = 5;

/// The file of the secure store when `global_settings.secure_store_file` names none.
pub const DEFAULT_SECURE_STORE_FILE: &str = "~/.my-reverse-proxy-secure";

/// How long a gateway client waits for its TCP connect when its `connect_timeout` says nothing.
pub const DEFAULT_GATEWAY_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// How long the admin mode of MCP stays open when the call which opens it names no minutes, and
/// the longest it may be opened for at once.
pub const DEFAULT_MCP_ADMIN_MODE_MINUTES: u64 = 10;
pub const MAX_MCP_ADMIN_MODE_MINUTES: u64 = 60;
// How often the urls of `real_time_configurations` are read, and how long a read of one may take.
pub const DEFAULT_REAL_TIME_CONFIGURATIONS_REFRESH_INTERVAL: Duration = Duration::from_secs(10);
pub const DEFAULT_REAL_TIME_CONFIGURATIONS_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
// The biggest answer of a url of `real_time_configurations` read.
pub const MAX_REAL_TIME_CONFIGURATION_RESPONSE_SIZE: usize = 16 * 1024 * 1024;
// Minimum spacing between REVIVE dials to a dead pool entry. Repeat revive
// attempts inside the window fail fast instead of re-dialing, so a down
// upstream costs at most one revive dial per window per entry. (Does not
// rate-limit Path 0 growth of a below-target pool or on-demand WS connects.)
pub const DEFAULT_POOL_REVIVE_COOLDOWN: Duration = Duration::from_millis(500);
// How long a request may wait for an in-flight revive (the entry's
// revive_lock) when EVERY entry of the pool is dead, before failing fast.
// Bounds the waiters only: the one request that wins the lock dials with the
// full connect_timeout — someone has to, and it recovers the pool the moment
// the upstream is back.
pub const DEFAULT_POOL_DEAD_POOL_WAIT_BUDGET: Duration = Duration::from_millis(500);
// h2 transport keep-alive: a PING frame every interval; no answer within the
// timeout closes the connection (flipping the client's is_alive), so a dead
// idle socket is detected before user traffic ever touches it.
pub const DEFAULT_H2_KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(10);
pub const DEFAULT_H2_KEEP_ALIVE_TIMEOUT: Duration = Duration::from_secs(2);
// Per-pool cap on concurrent on-demand (disposable) overflow connections. Below
// the global MAX_DISPOSABLE ceiling so one saturated upstream cannot starve the
// process-wide budget for the others.
pub const DEFAULT_MAX_DISPOSABLES_PER_POOL: usize = 50;
// Read/stream inactivity timeout for MCP upstream connections. MCP streamable-
// HTTP / SSE bodies can idle far longer than DEFAULT_READ_TIMEOUT with no
// keepalive, so MCP locations get a large value to avoid dropping a healthy but
// idle stream. (TCP RST/FIN still surfaces immediately regardless of this.)
pub const DEFAULT_MCP_READ_TIMEOUT: Duration = Duration::from_secs(60 * 60);

// CAP — never a fill target — on one relay step of an HTTP/1.1 body between the
// client and an upstream. Whatever has arrived is forwarded immediately: the pump
// NEVER waits for more bytes to round a step up to this size. It only stops a
// single write from carrying an unbounded block (the read buffer is 1 MB, so
// without the cap one write could carry a megabyte at a time), which keeps the
// pump moving in steady steps and bounds what one step holds. The body itself is
// never accumulated in either direction.
pub const BODY_RELAY_CHUNK_SIZE: usize = 256 * 1024;

pub const HTTP_CR_LF: &[u8] = b"\r\n";

pub const AUTHORIZED_COOKIE_NAME: &str = "x-authorized";

pub mod location_type {

    pub const MCP: &str = "mcp";
    pub const MCP_H2: &str = "mcp-h2";
    pub const STATIC: &str = "static";
    pub const DYNAMIC: &str = "dynamic";
}

/// `Strict-Transport-Security` of an https endpoint with `hsts: true`, on both http paths.
pub const HSTS_VALUE: &str = "max-age=31536000; includeSubDomains; preload";

/// Why a unix socket - a listen endpoint, an upstream or a gateway target - is refused when the
/// settings are compiled on a platform without unix sockets.
#[cfg(not(unix))]
pub const UNIX_SOCKETS_NOT_SUPPORTED: &str = "unix sockets are not supported on this platform";
