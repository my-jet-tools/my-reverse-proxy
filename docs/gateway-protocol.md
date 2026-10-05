# Gateway Protocol

Internal description of the wire protocol used between `my-reverse-proxy`
peers (gateway server and gateway clients). This document covers the
transport, handshake, frame types, batching/compression and limits.

## Goals

- **Forward secrecy.** Compromise of a long-term key must not decrypt past
  recorded sessions. Achieved via ephemeral X25519 ECDHE; the symmetric AES
  key is derived per connection and exists only in process memory.
- **SSH-style authentication.** The server keeps a list of authorized
  Ed25519 public keys. Each client signs the handshake with its private key.
  No CA, no host key — trust on first use is implicit.
- **Strict handshake, negotiated extensions.** The handshake is not
  extensible: a peer with another `protocol_version` fails at handshake.
  What was added to version 1 since is negotiated (see Capabilities): a peer
  advertises a feature in its pings and uses it only with a peer which
  advertised it too - a peer which predates a feature keeps working, without
  it, with one which has it.

Out of scope: server authentication. Client does not verify server identity.
A network-level MITM that does not have any client's private key cannot read
or inject; an MITM that can mount an active proxy attack is also held back
by the signed transcript (server cannot present a different ephemeral key
to client without knowing a client's private key). Adding a server host key
is a future extension.

## Transport frame

Every byte on the wire after the TCP connection is established belongs to a
sequence of frames:

```
[u32 LEN little-endian] [AES-CBC-encrypt(u8 TYPE || PAYLOAD)]
```

- `LEN` is plaintext, 4 bytes, little-endian. Length of the encrypted body.
- The body, after AES-CBC decryption, is `u8 TYPE` followed by the
  type-specific `PAYLOAD`.
- The AES key/IV (48 bytes total: 32-byte key + 16-byte IV) is the
  per-connection session key derived during handshake. The same key is used
  by both directions for the lifetime of the TCP connection.

There is no other framing. Wire = `(LEN, encrypted(TYPE, PAYLOAD)) × N` with
no separators.

`MAX_PAYLOAD_SIZE = 5 MiB` (the encrypted body). Frames exceeding this
limit are rejected and the connection is closed.

## Handshake

The first two frames on the wire are the connection-level handshake. Their
bodies are **plaintext** (no AES yet — the session key does not exist until
both sides finish this exchange). They use the same `[u32 LEN]`
length prefix as regular frames, so the framing reader is uniform.

### `ClientHandshake` (Client → Server)

| Field            | Size  | Notes                                                          |
|------------------|-------|----------------------------------------------------------------|
| `protocol_version` | 1 B | currently `1`                                                  |
| `client_eph_pub`   | 32 B | X25519 ephemeral public key                                    |
| `client_id_pub`    | 32 B | Ed25519 long-term public key (used to look up authorized list) |
| `timestamp_us`     | 8 B | i64 LE microseconds since epoch (anti-replay)                 |
| `gateway_name_len` | 4 B | u32 LE                                                         |
| `gateway_name`     | var | UTF-8 bytes                                                    |
| `signature`        | 64 B | Ed25519 signature over `client_eph_pub‖timestamp_us‖gateway_name` |

### `ServerHandshake` (Server → Client)

| Field           | Size | Notes                          |
|-----------------|------|--------------------------------|
| `protocol_version` | 1 B | must match client's version |
| `server_eph_pub`   | 32 B | X25519 ephemeral public key |

### Server-side validation

1. Parse `ClientHandshake`. Reject (close connection) if:
   - `protocol_version` is not supported,
   - `client_id_pub` is not in the configured authorized list,
   - `signature` does not verify against `client_id_pub`,
   - `timestamp_us` is more than 60 seconds away from `now()`.
2. Generate a fresh X25519 ephemeral keypair, send `ServerHandshake`.

### Session key derivation

Both sides compute, independently:

```
shared      = X25519(my_eph_priv, their_eph_pub)
key_material = HKDF-SHA256(
    ikm  = shared,
    salt = client_eph_pub || server_eph_pub,
    info = "gateway-session-v1",
    out  = 48 bytes,
)
session_key = AesKey {
    key = key_material[0..32],
    iv  = key_material[32..48],
}
```

The ephemeral private keys are `zeroize`'d immediately after `shared` is
computed. From here on, every frame uses `session_key`.

## Application frame types

After the handshake, all frames carry one of the following `TYPE` codes:

| Code | Name                              | Direction      |
|------|-----------------------------------|----------------|
| `0`  | `PING`                            | both           |
| `1`  | `PONG`                            | both           |
| `3`  | `CONNECT`                         | both           |
| `4`  | `CONNECT_OK`                      | both           |
| `5`  | `CONNECTION_ERROR`                | both           |
| `6`  | `SEND_PAYLOAD` (forward)          | both           |
| `7`  | `RECEIVE_PAYLOAD` (backward)      | both           |
| `8`  | `UPDATE_PING_TIME`                | both           |
| `9`  | `GET_FILE_REQUEST`                | both           |
| `10` | `GET_FILE_RESPONSE`               | both           |
| `11` | `SYNC_SSL_CERTIFICATES`           | server → client |
| `12` | `SYNC_SSL_CERTIFICATES_REQUEST`   | client → server |
| `13` | `SYNC_SSL_CERTIFICATE_NOT_FOUND`  | server → client |
| `14` | `CONNECT_FC`                      | both           |
| `15` | `WINDOW_UPDATE`                   | both           |
| `16` | `FIN`                             | both           |
| `17` | `RST`                             | both           |
| `20` | `COMPRESSED_BATCH`                | both           |

`CONNECT_FC` and `WINDOW_UPDATE` belong to flow control and are sent only to
a peer which advertised `CAP_FLOW_CONTROL`; `FIN` and `RST` are explicit ends
of a tunnelled connection, sent only to a peer which advertised
`CAP_FIN_RST`. A peer built without an extension - one which predates it -
takes its frames for unknown types and closes the connection.

The legacy `HANDSHAKE` (code `2`) packet has been removed — its job is now
covered by the connection-level handshake described above.

The byte-level layout of each `PAYLOAD` is identical to the previous
revision of the protocol, with the exception of `SEND_PAYLOAD` /
`RECEIVE_PAYLOAD` / `GET_FILE_RESPONSE`, which no longer carry an inner
per-payload gzip flag. Whole-batch zstd via `COMPRESSED_BATCH` replaces it.

## Capabilities

`PING` may carry one capability byte after the type:

```
PING  [u8 TYPE = 0]  or  [u8 TYPE = 0][u8 CAPS]
```

- `CAPS` bit 0 (`0x01`, `CAP_FLOW_CONTROL`): per-connection flow control,
  see Flow control.
- `CAPS` bit 1 (`0x02`, `CAP_FIN_RST`): explicit ends of a tunnelled
  connection - `FIN` and `RST`, see Closing.
- The other bits are reserved: sent as 0, ignored. Bytes after `CAPS` are
  ignored. Peers which predate capabilities read `PING` by its type alone.
  `PONG` is unchanged.
- The client pings as soon as it is connected and then every 3 seconds, each
  `PING` carrying its capabilities - the bare frame if it has none.
- A server with capabilities sends one `PING` carrying them as its first
  frame after the handshake; a client which predates capabilities ignores
  it. The server answers every `PING` with a bare `PONG`.
- The server takes the client's capabilities from the first `PING` it gets;
  the client takes the server's from the first `PING` or `PONG` it gets - a
  `PONG` first means the server has none. They hold for the life of the
  gateway connection. A feature is on when both ends have it.
- A connect waits until the other end's capabilities are known - next to
  nothing on the client, about a round trip on the server, up to 3 seconds
  with a client which predates capabilities - but never longer than its
  connect timeout. A connection opened without them has no flow control for
  its whole life.
- A peer built with a feature accepts its frames at any time, whether it has
  seen the other end's capabilities yet or not.

## `COMPRESSED_BATCH`

Sender-driven batching with optional whole-batch compression. Active only
when the sender has compression enabled; the receiver always understands
this type.

### `COMPRESSED_BATCH` body

```
[u8 TYPE = 20][u8 ALGO][compressed_bytes]
```

- `ALGO`:
  - `0` — zstd, level 3 (default).
  - `1`, `2` — reserved for future algorithms. Receiving an unknown algo
    closes the connection.
- `compressed_bytes` — output of the algorithm applied to a stream of
  inner frames concatenated together: `(LEN, TYPE, PAYLOAD) × N`, exactly
  as they would appear on the wire **if they were not encrypted**.

### Send-side algorithm

The writer task queues the plaintext inner frames `[u32 len][u8 type][body]`
that arrive while a previous `write_all` await is pending. On every flush
boundary (the moment the previous write finishes and the writer is ready to
send again):

1. Take a batch: first the queued `WINDOW_UPDATE` frames (up to 4 KiB of
   them), then whole frames off the front of the queue: at least one, then
   more while they stay within `MAX_WRITE_BATCH = 256 KiB`. Whatever does not
   fit waits for the next flush. A batch which leaves `WINDOW_UPDATE`s behind
   takes nothing else: no frame ever overtakes one queued before it.
2. If the connection's `compress` flag is `false`:
   - Encrypt each inner frame individually, prepend its own outer `[u32 LEN]`,
     concatenate, write in one syscall.
3. If `compress` is `true`:
   - Run `zstd::compress(batch, level=3)`.
   - Build outer body: `[TYPE=COMPRESSED_BATCH][ALGO=0][compressed_bytes]`.
   - Encrypt the outer body, prepend `[u32 LEN]`, write in one syscall.

A single `write_all` to the socket is emitted per flush — either many
independent frames concatenated (no compression) or a single
`COMPRESSED_BATCH` frame. Capping the batch is what keeps a
`COMPRESSED_BATCH` far below the receiver's limits however much data is
queued: a batch built from everything queued behind a slow write would grow
past `MAX_PAYLOAD_SIZE` under a bulk transfer, and the receiver closes the
connection on such a frame.

The queue is a single FIFO with one exception, `WINDOW_UPDATE`, which goes
out with the next batch: a control frame (a ping, a `CONNECT`, a close)
waits behind every frame queued before it — up to the 2 MiB write budget of
data — and behind whatever the kernel send buffer still holds. On a slow,
saturated link that is seconds (about 17 s at 1 Mbit/s).

### Receive-side algorithm

The reader's main loop is unchanged for the outer step:

1. Read `[u32 LEN]`, read body, decrypt.
2. `TYPE = decrypted[0]`.
3. If `TYPE == COMPRESSED_BATCH`:
   - `algo = decrypted[1]`. If unknown, close connection.
   - `decompressed = decompress(decrypted[2..])`, stopping one byte past
     `MAX_DECOMPRESSED_BATCH_SIZE`. Reject and close if it got that far.
   - Iterate `[u32 inner_len][u8 inner_type][inner_payload]` over
     `decompressed`, dispatching each through the regular packet handler.
4. Otherwise: dispatch `decrypted` through the regular packet handler.

### Limits

- `MAX_PAYLOAD_SIZE = 5 MiB` — outer frame body.
- `MAX_DECOMPRESSED_BATCH_SIZE = 16 MiB` — defense against decompression
  bombs.
- `MAX_PAYLOAD_CHUNK = 256 KiB` — the most payload a sender puts into one
  `SEND_PAYLOAD` / `RECEIVE_PAYLOAD`; a bigger write goes out as several
  frames.
- `MAX_FILE_RESPONSE_SIZE = MAX_PAYLOAD_SIZE - 64 KiB` — a
  `GET_FILE_RESPONSE` is a single frame, so a bigger file is answered with
  the error status instead of a frame the peer would close the connection
  on.
- At most 4 file responses are prepared at a time per gateway connection;
  the file is read only once a slot is free. The requester waits 60 seconds
  for the whole round trip; the serving side has half of it to wait for a
  slot, read the file and queue the response, and drops a response it could
  not queue by then. Only regular files are served, and the read itself is
  capped — a device or procfs file reports a size of 0.

## Tunnelled connections

### Connection ids

Both ends open connections over one gateway connection, each numbering its
own, and the frames of a connection name it by id alone. The ids are
therefore allocated apart: the server sets bit 31
(`SERVER_CONNECTION_ID_FLAG`) in every id it allocates, a client never does.
With overlapping numbering, closing the connection one end opened as id N
also closed the unrelated connection the other end opened as id N.

### Opening

The initiator registers the connection, sends `CONNECT` and waits for
`CONNECT_OK` or `CONNECTION_ERROR`, for at most the connect timeout plus 5
seconds. `CONNECT` carries the connect timeout in whole seconds in one byte:
the sender rounds a sub-second remainder up and clamps to 1..255 seconds,
the receiver treats 0 (sent by older peers for a sub-second timeout) as 1.

The acceptor connects to the target, registers the connection and only then
sends `CONNECT_OK` and starts reading the target — the initiator writes as
soon as it sees `CONNECT_OK`, and the target's first bytes go back under
the id, so neither may meet an id the acceptor does not know yet.

With flow control on, the initiator opens with `CONNECT_FC` instead:

```
[u8 TYPE = 14][u32 connection_id][u8 timeout_secs][u32 receive_window][remote_host]
```

`CONNECT` with the initiator's receive window inserted before the host. The
acceptor refuses a window under 1 MiB with `CONNECTION_ERROR`. Once it has
connected to the target and registered the connection, it sends a
`WINDOW_UPDATE` with its own receive window, then `CONNECT_OK` - both in
order - then starts reading the target; an initiator whose credit at `CONNECT_OK` is under 1 MiB
fails the connect. The frame which opened a connection decides for its whole
life, on both ends, whether it is flow controlled: one opened with `CONNECT`
- with a peer which predates capabilities, or when they did not arrive
within the connect timeout - has no flow control, as before. Both kinds
share a gateway connection.

### Closing

A tunnelled connection ends in both directions at once - there is no
half-close: the end of either direction ends the connection. The end says
how the connection ended:

```
FIN  [u8 TYPE = 16][u32 connection_id]
RST  [u8 TYPE = 17][u32 connection_id][reason: UTF-8, may be empty]
```

- `FIN`: closed cleanly - what the sender sent before it is the whole
  stream. The initiator's reader gets the buffered payloads and then EOF.
  The acceptor hands the target what it received and then shuts the
  socket's write side down: the target gets the end of the stream. A tail
  the target does not take within 30 seconds is given up on, and the target
  connection is reset instead, so the target does not take a stream cut
  short for a complete one.
- `RST`: broken - what the sender sent may be cut short. The initiator's
  reader gets the buffered payloads and then an error, as from a reset
  socket. The acceptor drops what it has not handed to the target yet and
  resets the target connection at once (`SO_LINGER` 0): the target gets an
  error, not an end of stream which would pass for a whole one.
- Both are queued behind the connection's data frames: everything sent
  before still arrives first. A unix-socket target can not be reset: it sees
  the end of the stream.
- A TCP reset is best effort: the OS may drop the reset of a connection
  closed in the middle of a transfer (macOS does on loopback, and
  rate-limits the reset it would send next). A target which only reads then
  learns of it when it next writes, or from its own timeout - never as an end
  of stream.

`FIN` and `RST` go only to a peer which advertised `CAP_FIN_RST`. To one
which did not, the end goes as `CONNECTION_ERROR`, whose text tells the two
apart as earlier versions write it: an empty text (the initiator closing) or
the acceptor's `ReadLoop. Connection to <target> with id:<id> is disconnected`
(the target closed cleanly) reads as `FIN`, any other text as `RST`. A peer
which predates `CAP_FIN_RST` ends a connection the same way on any
`CONNECTION_ERROR`: as an acceptor it flushes and shuts down even after the
initiator failed. `CONNECTION_ERROR` remains the answer to a `CONNECT` the
acceptor refuses and to a frame for an id the receiver does not know, and
reads as `RST`.

Who ends a connection how:

- The initiator sends `FIN` when its stream is closed - shut down, or
  dropped: the last clone, or either half of a split stream. It sends `RST`
  when the code using the stream fails: a byte pump whose read or write
  failed or whose write timed out (`copy_streams`, the websocket pumps). A
  session which went idle ends with `FIN`: nothing was lost.
- A byte pump which fails resets both ends: its writer's connection, and its
  reader's - the pump of the other direction stops at once and resets its
  writer too. A port forward's client socket is reset (`SO_LINGER` 0), a
  tunnel connection gets `RST`; a socket the pump can not reset is shut down
  (the HTTP client of a websocket tunnel, a direct, untunnelled upstream). A
  TLS client which closes without a close_notify ends its stream cleanly, and
  so does any websocket client once its Close went through.
- A send which finds the gateway connection gone - its writer failed, its
  teardown still to come - resets the connection at once: a caller which
  shuts the stream down after the failed write must not close it cleanly
  first.
- The acceptor sends `FIN` when the target closed its side and no write to
  it failed; `RST` when reading the target failed (it reset the
  connection), when a write to it failed, or when the initiator sent past
  its window.
- When the gateway connection goes down, every connection tunnelled through
  it is cut short: proxy streams read the buffered payloads and then an
  error, target connections are reset.
- Proxy streams of the HTTP clients (HTTP/1 and HTTP/2 upstreams over a
  gateway) end with `FIN` when they are dropped, also in the middle of a
  request: their own framing tells the target a message cut short.

When the target closes its side, the acceptor first lets its writer hand
the target what it still holds, for up to 2 seconds, and sends `FIN` only if
no write failed: a write still on its way may fail just then — on Linux a
target which reset reads as a plain EOF once the writer has taken the
reset — and then what the initiator sent did not all arrive.

The acceptor unregisters a connection and queues its `FIN` or `RST` in one
step, so a frame of that connection handled meanwhile either still finds it
or is answered after the end: a "not found" reply never overtakes a `FIN`
and turns a clean close into an error.

Neither end lets a socket go while it may still hold unread input — closing
a socket with unread data in it resets the connection, and a reset can make
the other side discard what it was just sent:

- When the peer closes the connection with `FIN`, the acceptor keeps
  reading the target, and drops what it reads, until its writer has flushed
  the last bytes and shut the write side down, and then for 2 seconds more
  for the target to close first. A connection which is reset lets its
  socket go at once.
- When the tunnel connection behind a byte pump closes, the pump keeps
  reading its client, and drops what it reads, until the client closes: for
  as long as the other pump of the connection writes the response tail,
  however long that takes at the client's speed, and after that for up to
  the write timeout, while the client reads what is still on its way - and
  not at all once the connection failed: then the client is reset anyway.

When a write to the target fails while the peer and the gateway connection
are fine — typically a target which answered early, a 413 for an upload,
and stopped reading — the acceptor keeps reading the target and forwarding
what it sends, for up to 5 seconds, and only then resets the connection
with `RST`. The 5 seconds hold even for a target which keeps its socket
full, and bound the forwarding as well as the reading - and the wait for
credit. That `RST` is sent by the acceptor's read loop alone, after its last
data frame: an end sent from elsewhere, as a control frame which takes no
write budget, could overtake a data frame still waiting for it.

A frame for an id the receiver does not know — a payload, or a
`CONNECT_OK` for a connect the initiator already gave up on — is answered
with `CONNECTION_ERROR`, so the other end resets its side too. A
`WINDOW_UPDATE`, `FIN` or `RST` for an id the receiver does not know is
dropped without an answer: frames crossing an end are normal.

When the gateway connection goes down, pending file requests fail too.

### One flag per tunnelled connection

Each tunnelled connection has one flag, shared by everything working for it.
Whatever fails first lowers it, and every loop of that connection stops on
it at once — also a loop blocked waiting on its other side, which is why the
flag is a cancellation token that wakes waiters, not a bare atomic.

- On the initiator the flag goes down when the connection is closed by the
  peer, by the gateway connection going down, by an explicit close, or when
  either half of a split stream is dropped: a byte pump drops its half when
  its loop ends, and a connection with one direction gone is of no use. A
  pump whose writer is the tunnel (`copy_streams`) stops on the flag even
  while it waits on an idle client; a writer waiting for budget or for
  credit stops too: the connection's send window is closed with it.
- On the acceptor the flag goes down when the peer ends the connection,
  when the gateway connection goes down, when the target's read side ends,
  or when a write to the target fails. A reset - `RST`, or the gateway
  connection going down - also stops the writer at once: it drops what it
  holds and resets the target connection. The read loop of the target stops on
  it — after the lingering read and, for a failed write, the forwarding of
  what the target still sends, both described under Closing. The read loop
  waiting for credit stops when the connection is unregistered - closed by
  the peer, or with the gateway connection - and, after a failed write, at
  the end of the forwarding.

### Backpressure

Data frames (`SEND_PAYLOAD`, `RECEIVE_PAYLOAD`, `GET_FILE_RESPONSE`) need a
share of a 2 MiB write budget per gateway connection before they are queued,
and give it back once they are on the socket. A producer which finds the
budget spent waits, so reading a fast target slows down to the speed of the
gateway link instead of piling its data up in memory. Control frames do not
take budget and never wait. The read loop only ever sends control frames: a
read loop waiting for its own writer would stop reading, and the peer it
stops reading from may be waiting on it the same way.

The budget is a FIFO queue. A stream written through `tokio::io::AsyncWrite`
(the hyper clients of http2 endpoints) keeps the size of its request while
it waits, whatever the caller passes in between, and writes what the grant
covers: asking for another size would requeue it behind every producer which
queued meanwhile, and a hyper h2 client grows its buffer with every new
stream, so under load it would never get its turn. Waiting for flow-control
credit is not sticky: only the connection's own writers wait on its window.

### Flow control

On a connection opened with `CONNECT_FC` each direction has a credit window:
the receiving end holds at most the receive window it advertised, and the
sender sends only what it has credit for.

```
WINDOW_UPDATE  [u8 TYPE = 15][u32 connection_id][u32 credit]
```

- Credit counts the payload of `SEND_PAYLOAD` / `RECEIVE_PAYLOAD` - the bytes
  after the connection id, after decompression.
- A sender starts with the window the other end advertised: the acceptor
  with the one in `CONNECT_FC`, the initiator with the acceptor's first
  `WINDOW_UPDATE`, which comes before `CONNECT_OK`. It takes credit for a
  payload before it asks for write budget, so a connection waiting for
  credit holds no budget and costs the others nothing. It asks for at most
  `MAX_PAYLOAD_CHUNK` at a time and uses all the credit it is given.
- A receiver advertises at least 1 MiB (8 MiB in this version): a smaller
  window is refused in `CONNECT_FC` and fails the connect as the first
  credit. It gives credit back for payload its consumer has taken - read by
  the proxy stream's reader on the initiator, written to the target on the
  acceptor - in `WINDOW_UPDATE`s of at least 512 KiB, and sends what it owes
  before that reaches window − `MAX_PAYLOAD_CHUNK`: a sender waiting for a
  chunk gets it once the consumer has caught up. Payload no consumer takes -
  after a close, after a failed write to the target - is not credited: its
  connection is ending.
- `WINDOW_UPDATE` is a control frame: no write budget, never waits. It is the
  one frame the writer does not keep in order: it goes out with the next
  batch, ahead of the queued frames, so one connection's credit never waits
  behind another connection's data - all but the acceptor's first one, which
  goes in order right before its `CONNECT_OK`. Pings keep their place. It names the
  connection by id alone - one this end opened or one the other end opened;
  the ends allocate ids apart.
- A peer which sends past the window it was given has that connection
  reset; the gateway connection and its other connections go on. The
  initiator's reader gets the buffered data and then an error; the target
  connection is reset.

So a connection holds at most one window per direction on its receiving
end, however slow its reader or target. A reader or target which stops
taking data stops its sender within a window; the data waits where it came
from - the target's socket, the client's write - as on a direct TCP
connection, and a close behind it arrives once the data before it has been
taken. Connections opened with `CONNECT` are not bounded: what a peer sends
faster than their reader consumes is buffered in memory on the receiving
side.

## Liveness

- The handshake must complete within 10 seconds on either side.
- The client pings as soon as it is connected, then every 3 seconds, and
  treats a connection without any incoming bytes for over 9 seconds as dead
  (it checks every 3 seconds, so a dead server is noticed after 10-13
  seconds). Every received chunk counts, not only complete frames, so a big
  frame on its way to the client is not mistaken for a dead peer. The
  client's pings get no priority: they queue behind its own outgoing data
  (only `WINDOW_UPDATE` frames go ahead of the queue; they say nothing about
  liveness). A client whose uplink stays saturated for over 9 seconds with
  nothing coming back takes the server for dead and closes everything. This
  is intended — a gateway link too slow for the traffic it carries is torn
  down rather than kept alive.
- Both read loops close a connection without any incoming bytes for 30
  seconds. On the server this is what finds a client which vanished without
  closing its socket.
- A tunnelled connection has no idle timeout of its own: it lives until it is
  closed, fails, or its gateway connection goes down. The byte pumps in front
  of it (a port forward, a websocket) end it once neither direction has moved
  bytes for their `read_timeout` (3 minutes by default). One direction going
  quiet while the other one moves data ends nothing.
- Closing a gateway connection ends its read loop as well, even one blocked
  on a socket whose peer is gone.
- A connection is registered under the gateway name the client sends. A
  reconnect displaces the previous registration, and the displaced
  connection is closed. A connection that ends unregisters only itself, so
  the teardown of an old connection never removes the registration of the
  new one.

## Configuration shape

YAML — relies on the existing `ssh:` registry for client private keys.

```yaml
ssh:
  gateway-london:
    private_key_file: "~/keys/gateway_id_ed25519"
    passphrase: "secret"

gateway_server:
  port: 5125
  authorized_keys:
    - "~/keys/gateway_london.pub"
    - "~/keys/gateway_amsterdam.pub"

gateway_clients:
  to-main:
    remote_host: "1.2.3.4:5125"
    ssh_credentials: "gateway-london"
    compress: true
```

- The client's private key is loaded by reading `private_key_file` from the
  named `ssh:` entry, decrypted with `passphrase` if present, parsed via
  the `ssh-key` crate. Only Ed25519 keys are accepted.
- The server's `authorized_keys` is a list of paths to standard `*.pub`
  files (one Ed25519 public key per file, OpenSSH text format). Files are
  read at startup; failure to read or parse any of them fails fast.
- `compress: true` on a client enables sender-side `COMPRESSED_BATCH` for
  that client's outbound traffic. Receiver always handles both formats.

## Threat model and limitations

- **Passive observation:** Forward-secret. Recording the entire wire and
  later compromising any long-term key (server-side or client-side) does
  not reveal past traffic.
- **Active MITM without any client private key:** Cannot complete the
  server-side handshake (requires forging a signature). The client side
  may complete a handshake with the MITM but the MITM cannot relay it to
  the real server, so traffic does not flow.
- **Active MITM that controls a client's private key:** Can impersonate
  that client. There is no host pinning to detect this on the client
  side. Not in scope at this revision.
