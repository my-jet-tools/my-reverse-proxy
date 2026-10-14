# Gateway Protocol

Internal description of the wire protocol used between `my-reverse-proxy`
peers (gateway server and gateway clients). This document covers the
transport, handshake, frame types, batching/compression and limits.

## Goals

- **Forward secrecy.** Compromise of a long-term key must not decrypt past
  recorded sessions. Achieved via ephemeral X25519 ECDHE; the symmetric keys
  are derived per connection and exist only in process memory.
- **SSH-style authentication of the client.** The server keeps a list of
  authorized Ed25519 public keys. Each client signs the handshake with its
  private key. No CA, and no host key: the client does not authenticate the
  server (see Threat model).
- **Speed.** A frame is sealed and opened with the AES instructions of the
  CPU, in place; batches are packed with LZ4 or Zstandard, whichever the
  compression level of the connection says; reading and opening a frame is
  one task, unpacking and handling its batch another.
- **One version, nothing negotiated.** The handshake is not extensible: a
  peer with another `protocol_version` fails at handshake — the end which
  gets its frame refuses it, logs both versions and closes the connection.
  Both ends of a gateway connection are version 2 — the frames, the cipher
  and the handshake of version 1 are gone, and nothing of it is kept for a
  peer which still speaks it. Every tunnelled connection is flow controlled
  and ends with `FIN` or `RST`: the protocol has no optional features, and
  nothing is advertised or negotiated once the handshake is done.

Out of scope: server authentication. The client does not verify the server's
identity: what the server sends in the handshake is an ephemeral key with
nothing signed. Somebody who only watches the wire can not read it; somebody
who can answer the client's connection in place of the server can (see
Threat model). The gateway is meant for links between hosts which list each
other's addresses. Adding a server host key is a future extension.

## Transport frame

Every byte on the wire after the handshake belongs to a sequence of frames:

```
[u32 LEN little-endian] [AES-256-GCM(BATCH)] [16-byte TAG]
```

- `LEN` is plaintext, 4 bytes, little-endian: the length of what follows —
  the ciphertext and the tag.
- A frame carries one batch (see Batches): the inner frames its writer had
  queued when it wrote.
- Each direction has a key of its own, derived during the handshake. The
  nonce of a frame is its number in its direction under the current key —
  4 zero bytes and a 64-bit big-endian counter, from 0 — and it does not
  travel: both ends count the frames.
- A frame which is not the next one its peer sealed — changed on the way,
  repeated, out of its turn, sealed for the other direction — does not open,
  and the connection is closed. Nothing of it reaches a handler.
- After 64 GiB of frames under one key (their `LEN`s added up) the next key
  of the direction is derived from the current one —
  `HKDF-SHA256(ikm = key, info = "gateway-rekey-v2")`, 32 bytes — and the
  counter starts at 0 again. Both ends count the same frames, so they change
  the key behind the same frame, and nothing travels to say so.

There is no other framing. Wire = `(LEN, sealed(BATCH)) × N` with no
separators.

`MAX_PAYLOAD_SIZE = 5 MiB` — the most `LEN` may say. A frame which says more
— or 16 bytes or less: a tag with nothing to carry — is rejected and the
connection is closed.

## Handshake

The first two frames on the wire are the connection-level handshake. Their
bodies are **plaintext** (the session keys do not exist until both sides
finish this exchange). They use the same `[u32 LEN]` length prefix as
regular frames.

### `ClientHandshake` (Client → Server)

| Field            | Size  | Notes                                                          |
|------------------|-------|----------------------------------------------------------------|
| `protocol_version` | 1 B | `2`                                                            |
| `compression`      | 1 B | the compression level of this connection, for both directions: `0` — off, from `1` on — a row of the table in [gateway-compression.md](gateway-compression.md) |
| `client_eph_pub`   | 32 B | X25519 ephemeral public key                                    |
| `client_id_pub`    | 32 B | Ed25519 long-term public key (used to look up authorized list) |
| `timestamp_us`     | 8 B | i64 LE microseconds since epoch (anti-replay)                 |
| `gateway_name_len` | 4 B | u32 LE                                                         |
| `gateway_name`     | var | UTF-8 bytes                                                    |
| `signature`        | 64 B | Ed25519 signature over `"gateway-handshake-v2:"‖client_eph_pub‖timestamp_us‖compression‖gateway_name` |

The level is under the signature: a link which changed it on the way would
leave the two ends packing differently.

### `ServerHandshake` (Server → Client)

| Field           | Size | Notes                          |
|-----------------|------|--------------------------------|
| `protocol_version` | 1 B | `2`                         |
| `server_eph_pub`   | 32 B | X25519 ephemeral public key |

### Server-side validation

1. Parse `ClientHandshake`. Reject (close connection) if:
   - `protocol_version` is not 2 — looked at before anything else, since the
     frame of another version is laid out another way,
   - `compression` is a level this side has no row for — a client of a
     build whose table is longer,
   - `client_id_pub` is not in the configured authorized list,
   - `signature` does not verify against `client_id_pub`,
   - `timestamp_us` is more than 60 seconds away from `now()`.
2. Generate a fresh X25519 ephemeral keypair, send `ServerHandshake`.

The client rejects a `ServerHandshake` of another `protocol_version` the
same way.

### Session key derivation

Both sides compute, independently:

```
shared      = X25519(my_eph_priv, their_eph_pub)
key_material = HKDF-SHA256(
    ikm  = shared,
    salt = client_eph_pub || server_eph_pub,
    info = "gateway-session-v2",
    out  = 64 bytes,
)
client_to_server_key = key_material[0..32]    // what the client seals with
server_to_client_key = key_material[32..64]   // what the server seals with
```

The ephemeral private keys are `zeroize`'d immediately after `shared` is
computed. From here on, every frame is sealed with the key of its direction.

## Inner frame types

A batch carries inner frames, `[u32 LEN][u8 TYPE][PAYLOAD]` each, with one of
the following `TYPE` codes:

| Code | Name                              | Direction      |
|------|-----------------------------------|----------------|
| `0`  | `PING`                            | client → server |
| `1`  | `PONG`                            | server → client |
| `4`  | `CONNECT_OK`                      | both           |
| `5`  | `CONNECTION_ERROR`                | both           |
| `6`  | `SEND_PAYLOAD` (forward)          | both           |
| `7`  | `RECEIVE_PAYLOAD` (backward)      | both           |
| `8`  | `UPDATE_PING_TIME`                | client → server |
| `9`  | `GET_FILE_REQUEST`                | both           |
| `10` | `GET_FILE_RESPONSE`               | both           |
| `11` | `SYNC_SSL_CERTIFICATES`           | server → client |
| `12` | `SYNC_SSL_CERTIFICATES_REQUEST`   | client → server |
| `13` | `SYNC_SSL_CERTIFICATE_NOT_FOUND`  | server → client |
| `14` | `CONNECT`                         | both           |
| `15` | `WINDOW_UPDATE`                   | both           |
| `16` | `FIN`                             | both           |
| `17` | `RST`                             | both           |

A type which is not in the table closes the gateway connection.

Codes `2` (`HANDSHAKE`), `3` (`CONNECT` without a receive window) and `20`
(`COMPRESSED_BATCH`) of version 1 are not frame types any more: the
handshake is the connection-level one described above, a connection is
opened with the `CONNECT` which carries the initiator's window, and every
frame carries a batch. Their codes are not given to anything else.

## Ping

```
PING  [u8 TYPE = 0]
PONG  [u8 TYPE = 1]
```

Neither carries anything, and both are read by the type alone. The client
sends a `PING` as soon as it is connected and then every 3 seconds; the
server answers each with a `PONG`; the client answers a `PONG` with
`UPDATE_PING_TIME` — the round trip it measured, which the server shows as
the ping time of the connection. The server does not ping, and a client
which gets a `PING` ignores it. What the pings are for is under Liveness.

## Batches

What a frame carries is a batch: the inner frames its writer had queued, one
after another, as they are or packed.

### Batch body

```
[u8 KIND = 0][inner frames]                        stored
[u8 KIND = 1][u32 RAW_LEN][LZ4 block]              packed with LZ4
[u8 KIND = 2][u32 RAW_LEN][Zstandard frame]        packed with Zstandard
[u8 KIND = 3][u32 RAW_LEN][piece of a stream]      packed with Zstandard, one stream
```

- `KIND = 0` — the inner frames follow as they are.
- `KIND = 1` — the inner frames, `RAW_LEN` bytes of them, packed as one LZ4
  block.
- `KIND = 2` — the same, packed as one Zstandard frame. The frame carries
  neither its content size nor a checksum: the batch says its size, and the
  frame around it is sealed.
- `KIND = 3` — the inner frames, `RAW_LEN` bytes of them, as the next piece
  of one Zstandard stream which runs for a whole direction of the
  connection. The stream starts with the first batch of this kind and ends
  with the connection; a piece ends where the stream is flushed, so it
  unpacks to the whole batch and to nothing else. A piece is packed with
  every piece before it for a history, and is unpacked after them, in
  their order — the order of the frames, which the sealing holds. The
  stream carries neither a content size nor a checksum, and its window is
  4 MiB at the most: a receiver takes no stream which asks for more. A
  piece which unpacks to more or to fewer bytes than its `RAW_LEN` closes
  the connection.
- Any other kind closes the connection.
- The inner frames are `(LEN, TYPE, PAYLOAD) × N`. A batch they do not fill
  exactly — a frame cut short, bytes left behind the last one — closes the
  connection.

### Compression

Compression is the setting of the client: `compress` is a level — `0` is
off, and a level from `1` on is a row of the table in
[gateway-compression.md](gateway-compression.md), an algorithm and its own
level. It travels in the handshake of the client and holds for both
directions: the server packs what it sends over the connection of a client
with the level that client asked for, and has no setting of its own.

The level is what a writer packs with. A batch says itself what it is packed
with — its `KIND` — and a receiver takes every kind at any time, whatever
the level of the connection. For the kinds 0 to 2 it needs nothing but the
batch to unpack it; a piece of a stream it unpacks with the stream of the
connection, which the pieces before it have gone through.

At the levels which pack a batch on its own — LZ4 and a Zstandard frame — a
writer packs every batch which is big enough for its algorithm to save
anything — 64 bytes for LZ4, 128 for Zstandard — and sends it packed when
that is smaller: what it is packed to and its `RAW_LEN` together shorter
than the frames. Otherwise the batch goes stored: what can not be packed —
TLS, media, what is packed already — costs the attempt, which both
algorithms give up on early, and travels as it is. A batch never goes out
bigger than its frames and a byte. Nothing of the batches before it is
used, so a batch of many frames packs better than the same frames sent one
by one — see the document for how much.

At the levels of one stream every batch of 32 bytes or more is a piece of
the stream, whether it packs or not: it is what the batches after it are
packed with. What does not pack Zstandard puts into the stream as it is, so
such a piece is bigger than its frames — by its 5 bytes and 3 more for
every 128 KiB. A batch under 32 bytes — a ping, a window update — goes
stored: it is no part of the stream, and the receiver leaves its stream
where it is for it.

A batch is packed by the writer task, between two writes.

### Send-side algorithm

The writer task queues the plaintext inner frames `[u32 len][u8 type][body]`
that arrive while a previous `write_all` await is pending. On every flush
boundary (the moment the previous write finishes and the writer is ready to
send again):

1. Take what is in the channel already: frames sent one right after another
   — a `WINDOW_UPDATE` and the `CONNECT_OK` behind it — go out together.
2. Take the small frames: first the queued `WINDOW_UPDATE` frames (up to
   4 KiB of them), then the frames off the front of the queue up to the
   first one bigger than 4 KiB, while they stay within
   `MAX_WRITE_BATCH = 260 KiB`. They are a batch of their own. With
   `WINDOW_UPDATE`s left behind nothing else is taken: no frame ever
   overtakes one queued before it.
3. If the frame now at the front of the queue is a big one, take a second
   batch: that frame, then more frames of any size while they stay within
   `MAX_WRITE_BATCH` — a whole payload chunk and the small frames queued
   behind it. Whatever does not fit waits for the next flush.
4. Write each batch behind 4 bytes left for `LEN` — packed or stored, see
   Compression — seal it in place, put the tag behind it and `LEN` in front.

A single `write_all` to the socket is emitted per flush — one frame, or two.
A frame is handled only once all of it has arrived, so what is queued ahead
of a big inner frame — credit, a `PONG`, the answer to a connect — travels in
a frame of its own and is handled as soon as it is there, not once the
megabytes behind it are. Capping the batch is what keeps a frame far below
the receiver's limits however much data is queued: a batch built from
everything queued behind a slow write would grow past `MAX_PAYLOAD_SIZE`
under a bulk transfer, and the receiver closes the connection on such a
frame.

The queue is a single FIFO with one exception, `WINDOW_UPDATE`, which goes
out with the next batch: a control frame (a ping, a `CONNECT`, a close)
waits behind every frame queued before it — up to the 2 MiB write budget of
data, or a file response, which is one frame of up to 4.9 MiB and takes the
whole budget — and behind whatever the kernel send buffer still holds. On a
slow, saturated link that is seconds (about 17 s at 1 Mbit/s for the
budget, 40 s for such a file).

`TCP_NODELAY` is set on the gateway connection, on both ends: every frame is
written whole, so there is nothing for the kernel to wait for. It is set on
the acceptor's connection to the target too, and on the client socket of a
tcp port forward: what comes out of the tunnel is written as it comes.

### Receive-side algorithm

Two tasks per gateway connection, with two buffers of `MAX_PAYLOAD_SIZE`
between them (`DoubleBuffer` of `rust-extensions`), each allocated when it is
first read into:

- **The socket reader.** Reads `[u32 LEN]` and rejects a frame which is too
  big or carries nothing. Takes a buffer — waiting while both are still
  being handled, so it is never more than two frames ahead and the peer's
  writer slows down to the speed of this side — reads the frame into it,
  opens it in place and hands the batch over.
- **The read loop.** Takes the batches in the order they came. A packed one
  says how big it is unpacked: more than `MAX_DECOMPRESSED_BATCH_SIZE`
  closes the connection before any memory is taken for it, and so does a
  block which unpacks to another size. Then iterates
  `[u32 inner_len][u8 inner_type][inner_payload]`, dispatching each through
  the packet handler, and lets the buffer go — it is free for a frame again.

The socket reader may read and open the next frame while a batch is being
handled; how much the two really overlap is up to the scheduler, and on one
connection they mostly take turns. Whichever of the two tasks ends first — the socket closed or silent, a frame
which does not open, a batch which can not be handled — the other ends with
it, and the gateway connection is torn down.

### Limits

- `MAX_PAYLOAD_SIZE = 5 MiB` — a frame: the ciphertext and the tag.
- `MAX_DECOMPRESSED_BATCH_SIZE = 16 MiB` — the most a packed batch may say
  it unpacks to: defense against decompression bombs.
- `MAX_PAYLOAD_CHUNK = 256 KiB` — the most payload a sender puts into one
  `SEND_PAYLOAD` / `RECEIVE_PAYLOAD`; a bigger write goes out as several
  frames.
- `MAX_FILE_RESPONSE_SIZE = MAX_PAYLOAD_SIZE - 64 KiB` — a
  `GET_FILE_RESPONSE` is a single inner frame, so a bigger file is answered
  with the error status instead of a frame the peer would close the
  connection on. A response is a frame of its own — what is queued ahead of
  it goes in the frame before — and of the 64 KiB it takes 27 bytes: the
  header of its inner frame, the kind of the batch and the tag. The rest is
  spare.
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

```
CONNECT           [u8 TYPE = 14][u32 connection_id][u8 timeout_secs][u32 receive_window][remote_host]
CONNECT_OK        [u8 TYPE = 4][u32 connection_id]
CONNECTION_ERROR  [u8 TYPE = 5][u32 connection_id][reason: UTF-8]
```

The initiator registers the connection, sends `CONNECT` and waits for
`CONNECT_OK` or `CONNECTION_ERROR`, for at most the connect timeout plus 5
seconds. It may do so as soon as the handshake is done: nothing has to be
exchanged first. `CONNECT` carries the connect timeout in whole seconds in
one byte — the sender rounds a sub-second remainder up and clamps to 1..255
seconds, a receiver takes 0 for 1 — and the initiator's receive window (see
Flow control) before the host.

The acceptor refuses a window under 1 MiB with `CONNECTION_ERROR`, before it
connects to anything. Otherwise it connects to the target, registers the
connection and only then sends a `WINDOW_UPDATE` with its own receive
window and `CONNECT_OK` — in this order, neither ahead of its turn in the
queue — and starts reading the target: the initiator writes as soon as it
sees `CONNECT_OK`, and the target's first bytes go back under the id, so
neither may meet an id the acceptor does not know yet. An initiator whose
credit at `CONNECT_OK` is under 1 MiB fails the connect and closes the
connection.

`CONNECTION_ERROR` is the acceptor's refusal: connections this way are not
allowed, the id is taken, the window is out of range, or the connect to the
target failed or timed out. Its text is the reason: it becomes the error of
the connect, and nothing reads a meaning into it.

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

A connection which was opened ends with `FIN` or `RST`, and with nothing
else. `CONNECTION_ERROR` is not the end of a stream: it answers a `CONNECT`
the acceptor refuses (see Opening) and a frame for an id the receiver does
not know (below). An end which gets one for a connection it has ends that
connection as with `RST`, whatever the text says — the text is a reason for
the log and for the error of a connect still waiting, and is never read for
a meaning.

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
`WINDOW_UPDATE`, `FIN`, `RST` or `CONNECTION_ERROR` for an id the receiver
does not know is dropped without an answer: frames crossing an end are
normal.

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

Each direction of a tunnelled connection has a credit window: the receiving
end holds at most the receive window it advertised, and the sender sends
only what it has credit for.

```
WINDOW_UPDATE  [u8 TYPE = 15][u32 connection_id][u32 credit]
```

- Credit counts the payload of `SEND_PAYLOAD` / `RECEIVE_PAYLOAD` - the bytes
  after the connection id, as they are unpacked.
- A sender starts with the window the other end advertised: the acceptor
  with the one in `CONNECT`, the initiator with the acceptor's first
  `WINDOW_UPDATE`, which comes before `CONNECT_OK`. It takes credit for a
  payload before it asks for write budget, so a connection waiting for
  credit holds no budget and costs the others nothing. It asks for at most
  `MAX_PAYLOAD_CHUNK` at a time and uses all the credit it is given.
- A receiver advertises at least 1 MiB (8 MiB in this version): a smaller
  window is refused in `CONNECT` and fails the connect as the first
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
taken.

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
    compress: 2
```

- The client's private key is loaded by reading `private_key_file` from the
  named `ssh:` entry, decrypted with `passphrase` if present, parsed via
  the `ssh-key` crate. Only Ed25519 keys are accepted.
- The server's `authorized_keys` is a list of paths to standard `*.pub`
  files (one Ed25519 public key per file, OpenSSH text format). Files are
  read at startup; failure to read or parse any of them fails fast.
- `compress` on a client is the compression level of its gateway
  connection, in both directions: `0` or nothing — off, from `1` on — a row
  of the table in [gateway-compression.md](gateway-compression.md). The
  client says the level in its handshake and the server packs what it sends
  to it with the same. The server has no setting of its own. A level which
  is not in the table fails the startup. See Compression.

## Threat model and limitations

- **Passive observation:** Forward-secret. Recording the entire wire and
  later compromising any long-term key (server-side or client-side) does
  not reveal past traffic.
- **Active MITM without any client private key:** Cannot complete the
  server-side handshake (requires forging a signature), so it never reaches
  the real server. It can answer a client in the server's place, though:
  the client completes the handshake with whoever sends it an ephemeral
  key. Such a party reads what the client sends and can send it any frame a
  server may — a file request, a certificate, a `CONNECT` where
  `allow_incoming_forward_connections` is on.
- **A replayed `ClientHandshake`:** Accepted within the 60 seconds its
  timestamp allows. Whoever replays it can not use the session - it has no
  key for it - but the connection registered under that name is displaced.
- **Active MITM that controls a client's private key:** Can impersonate
  that client. There is no host pinning to detect this on the client
  side. Not in scope at this revision.
- **A frame changed on the way:** Does not open — the tag covers the whole
  batch — and the gateway connection is closed. Neither does one which is
  repeated, left out before, or taken from the other direction. `LEN` is
  not under the tag: a frame whose `LEN` was raised does not open either,
  but only once that many bytes have come in, and until then the connection
  looks alive while nothing it carries is handled.
