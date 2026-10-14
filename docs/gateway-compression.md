# Gateway compression

What `compress` of a gateway client means, what every level of it gives on
real data, and which level suits which link. The wire format is in
[gateway-protocol.md](gateway-protocol.md), under Batches.

## The levels

`compress` is a number: the compression level of the gateway connection.

| `compress` | packed with           |
|------------|-----------------------|
| `0`        | nothing — the default |
| `1`        | LZ4                   |
| `2`        | Zstandard, level 1    |
| `3`        | Zstandard, level 3    |
| `4`        | Zstandard, level 6    |
| `5`        | Zstandard, level 9    |
| `6`        | Zstandard, level 1, one stream |
| `7`        | Zstandard, level 3, one stream |
| `8`        | Zstandard, level 6, one stream |
| `9`        | Zstandard, level 9, one stream |

```yaml
gateway_clients:
  to-main:
    remote_host: "1.2.3.4:5125"
    ssh_credentials: "gateway-london"
    compress: 2
```

- It is the setting of the client and it holds for both directions: the
  client says the level in its handshake, and the server packs what it sends
  to that client with the same. The server has no setting of its own, and
  the clients of one server may each have a level of their own.
- Both ends have to know the level. A level which is not in the table fails
  the startup of the proxy whose client is set to it. A server refuses the
  handshake of a client which asks for a level it has no row for — a client
  of a newer build, with a longer table — and says so in its log; the
  client sees a closed connection and tries again.
- At the levels `1` to `5` a batch is packed on its own. At `6` to `9` the
  batches of a direction are one Zstandard stream: a batch is packed with
  everything sent before it — see "Small batches".
- At every level what can not be made smaller — TLS, media, what an upstream
  has compressed already — travels as it is: at `1` to `5` a batch is sent
  packed only when that is smaller, at `6` to `9` Zstandard puts it into the
  stream as it is, at 3 bytes for every 128 KiB.
- The level of a live connection is in the gateway status of the
  configuration API: `compress`, the number, and `compression`, what it
  packs with.
- The table is `LEVELS` in `src/tcp_gateway/session/compression.rs`. A new
  row goes to its end: a number goes on meaning what it means in the
  settings which are deployed. A new row belongs here and in the README as
  well, with what it gives.

## What a level gives

Measured through the whole tunnel — packed, sealed, written to a loopback
socket, read, opened, unpacked — over one gateway connection: a release
build on an Apple M4, 2026-10-13. A packed tunnel is as fast as one core of
the sending end packs, so these are the figures of that core; a server core
is usually slower, and all the speeds go down with it together.

The data:

- **API rows** — rows of a JSON answer: the names repeat, the values — ids,
  prices, times — do not.
- **HTTP messages** — requests of an API with their answers: the headers of
  a browser, a token and an id of its own in every one, a small JSON body.
- **JSON, repetitive** — answers of the crates.io index: the same few
  structures over and over.
- **HTML** — pages of the Rust standard library documentation.
- **minified JS** — an application bundle.
- **packed already** — bytes nothing packs: what TLS, media or a compressed
  body are to a packer.

Every sample is megabytes which do not repeat, sent in a row and over again
for as long as a run lasts, in batches of 256 KiB — a busy connection.

### How much smaller the data is on the wire

Bytes of the data for a byte on the wire, framing and sealing included.

| `compress` | packed with | API rows | HTTP messages | JSON, repetitive | HTML | minified JS | packed already |
|---|---|---|---|---|---|---|---|
| `0` | nothing | 1 | 1 | 1 | 1 | 1 | 1 |
| `1` | LZ4 | 2.30 | 6.58 | 12.35 | 6.65 | 2.37 | 1.00 |
| `2` | Zstandard 1 | 4.14 | 12.33 | 21.85 | 10.47 | 3.20 | 1.00 |
| `3` | Zstandard 3 | 3.94 | 12.03 | 21.50 | 11.04 | 3.50 | 1.00 |
| `4` | Zstandard 6 | 4.10 | 12.19 | 23.68 | 12.89 | 3.76 | 1.00 |
| `5` | Zstandard 9 | 4.30 | 12.47 | 24.17 | 13.22 | 3.81 | 1.00 |
| `6` | Zstandard 1, one stream | 4.16 | 12.66 | 23.02 | 13.73 | 3.27 | 1.00 |
| `7` | Zstandard 3, one stream | 3.88 | 11.97 | 21.44 | 18.01 | 3.64 | 1.00 |
| `8` | Zstandard 6, one stream | 4.02 | 12.02 | 23.91 | 22.97 | 4.04 | 1.00 |
| `9` | Zstandard 9, one stream | 4.22 | 11.94 | 24.02 | 25.69 | 4.22 | 1.00 |

### How fast the data moves

MiB/s of the data itself — what the application sends and gets — with
nothing but the processor in the way. The best of two to six runs, the
two directions averaged.

| `compress` | packed with | API rows | HTTP messages | JSON, repetitive | HTML | minified JS | packed already |
|---|---|---|---|---|---|---|---|
| `0` | nothing | 5 060 | 5 090 | 5 060 | 5 060 | 5 060 | 5 030 |
| `1` | LZ4 | 965 | 2 140 | 2 660 | 1 410 | 660 | 3 950 |
| `2` | Zstandard 1 | 660 | 1 460 | 2 240 | 1 230 | 515 | 3 290 |
| `3` | Zstandard 3 | 515 | 1 500 | 2 200 | 1 180 | 425 | 3 070 |
| `4` | Zstandard 6 | 170 | 410 | 745 | 355 | 155 | 2 410 |
| `5` | Zstandard 9 | 125 | 340 | 610 | 275 | 115 | 2 370 |
| `6` | Zstandard 1, one stream | 725 | 1 580 | 2 100 | 1 350 | 525 | 2 950 |
| `7` | Zstandard 3, one stream | 390 | 925 | 1 250 | 1 330 | 350 | 2 380 |
| `8` | Zstandard 6, one stream | 140 | 330 | 590 | 450 | 135 | 2 250 |
| `9` | Zstandard 9, one stream | 80 | 225 | 460 | 335 | 88 | 1 760 |

What the two tables say together:

- Zstandard 1 packs 1.4 to 1.9 times better than LZ4 and is 15 to 30 %
  slower. That is the biggest step of the table.
- Zstandard 3 saves no more than level 1 on JSON — a little less, in fact —
  and 5 to 10 % more on HTML and JS, at the same speed or somewhat below it.
- Zstandard 6 and 9 save another 17 to 26 % on HTML and JS and no more than
  10 % on JSON, and are 3 to 5 times slower than level 1.
- One stream on a busy connection: Zstandard 1 as one stream — `6` — packs
  as much as `2` or more, and moves about as fast: up to 10 % faster on
  rows, messages and HTML — the stream does not start its tables over for
  every batch — and 6 % slower on JSON.
- Where data repeats at a distance beyond one batch — HTML here — the
  stronger levels of one stream save far more than a batch at a time: `7`,
  `8` and `9` pack HTML 18, 23 and 26 times, against 11, 13 and 13 at `3`,
  `4` and `5`, and are faster on it too. On the other data they save about
  what `3` to `5` do and are slower: `7` by 18 to 43 % against `3`, `8` and
  `9` by 13 to 36 % against `4` and `5`.
- Data which does not pack costs the attempt and nothing else: it moves at
  gigabytes a second at every level.
- Without compression one gateway connection moves some 5 GiB/s — what
  would fill a link of 40 Gbit/s.

## What gets through a link

On a real link it is not the processor alone which is in the way. What gets
through is the lesser of two: what the level packs in a second, and what
the link carries of it — its speed multiplied by what the level saves.
While the link is the limit, a stronger level moves *more* data in a
second, and less traffic for it; once the packer is the limit, a stronger
level slows the tunnel down.

MiB/s of the data through a link of 100 Mbit/s — every level is faster than
the link, the strongest ones move the most:

| `compress` | packed with | API rows | HTTP messages | JSON, repetitive | HTML | minified JS | packed already |
|---|---|---|---|---|---|---|---|
| `0` | nothing | 12 | 12 | 12 | 12 | 12 | 12 |
| `1` | LZ4 | 27 | 78 | 145 | 79 | 28 | 12 |
| `2` | Zstandard 1 | 49 | 145 | 260 | 125 | 38 | 12 |
| `3` | Zstandard 3 | 47 | 145 | 255 | 130 | 42 | 12 |
| `4` | Zstandard 6 | 49 | 145 | 280 | 155 | 45 | 12 |
| `5` | Zstandard 9 | 51 | 150 | 290 | 160 | 45 | 12 |
| `6` | Zstandard 1, one stream | 50 | 150 | 275 | 165 | 39 | 12 |
| `7` | Zstandard 3, one stream | 46 | 145 | 255 | 215 | 43 | 12 |
| `8` | Zstandard 6, one stream | 48 | 145 | 285 | 275 | 48 | 12 |
| `9` | Zstandard 9, one stream | 50 | 140 | 285 | 305 | 50 | 12 |

Through a link of 1 Gbit/s — Zstandard 1 and 3, on their own and as one
stream, move the most; the stronger levels are slower than the link:

| `compress` | packed with | API rows | HTTP messages | JSON, repetitive | HTML | minified JS | packed already |
|---|---|---|---|---|---|---|---|
| `0` | nothing | 120 | 120 | 120 | 120 | 120 | 120 |
| `1` | LZ4 | 275 | 785 | 1 470 | 795 | 285 | 120 |
| `2` | Zstandard 1 | 495 | 1 460 | 2 240 | 1 230 | 380 | 120 |
| `3` | Zstandard 3 | 470 | 1 430 | 2 200 | 1 180 | 415 | 120 |
| `4` | Zstandard 6 | 170 | 410 | 745 | 355 | 155 | 120 |
| `5` | Zstandard 9 | 125 | 340 | 610 | 275 | 115 | 120 |
| `6` | Zstandard 1, one stream | 495 | 1 510 | 2 100 | 1 350 | 390 | 120 |
| `7` | Zstandard 3, one stream | 390 | 925 | 1 250 | 1 330 | 350 | 120 |
| `8` | Zstandard 6, one stream | 140 | 330 | 590 | 450 | 135 | 120 |
| `9` | Zstandard 9, one stream | 80 | 225 | 460 | 335 | 88 | 120 |

Through a link of 2.5 Gbit/s — LZ4 moves the most, and `6` on API rows:

| `compress` | packed with | API rows | HTTP messages | JSON, repetitive | HTML | minified JS | packed already |
|---|---|---|---|---|---|---|---|
| `0` | nothing | 300 | 300 | 300 | 300 | 300 | 300 |
| `1` | LZ4 | 685 | 1 960 | 2 660 | 1 410 | 660 | 300 |
| `2` | Zstandard 1 | 660 | 1 460 | 2 240 | 1 230 | 515 | 300 |
| `3` | Zstandard 3 | 515 | 1 500 | 2 200 | 1 180 | 425 | 300 |
| `4` | Zstandard 6 | 170 | 410 | 745 | 355 | 155 | 300 |
| `5` | Zstandard 9 | 125 | 340 | 610 | 275 | 115 | 300 |
| `6` | Zstandard 1, one stream | 725 | 1 580 | 2 100 | 1 350 | 525 | 300 |
| `7` | Zstandard 3, one stream | 390 | 925 | 1 250 | 1 330 | 350 | 300 |
| `8` | Zstandard 6, one stream | 140 | 330 | 590 | 450 | 135 | 300 |
| `9` | Zstandard 9, one stream | 80 | 225 | 460 | 335 | 88 | 300 |

## Choosing a level

The level which moves the most data in a second through a link of a given
speed — and, of the levels within a few percent of that, the one which
saves the most:

| the link | API rows | HTTP messages | JSON, repetitive | HTML | minified JS |
|---|---|---|---|---|---|
| 50 Mbit/s | `5` | `6` | `5` | `9` | `9` |
| 100 Mbit/s | `5` | `6` | `5` | `9` | `9` |
| 150 Mbit/s | `5` | `6` | `5` | `8` | `9` |
| 200 Mbit/s | `5` | `6` | `5` | `8` | `8` |
| 250 Mbit/s | `5` | `6` | `4` | `7` | `8` |
| 300 Mbit/s | `6` | `6` | `6` | `7` | `8` |
| 500 Mbit/s | `6` | `6` | `6` | `7` | `7` |
| 750 Mbit/s | `6` | `6` | `6` | `7` | `7` |
| 1 Gbit/s | `6` | `6` | `2` | `7` | `3` |
| 1.5 Gbit/s | `6` | `6` | `2` | `7` | `6` |
| 2 Gbit/s | `6` | `6` | `1` | `1` | `1` |
| 2.5 Gbit/s | `6` | `1` | `1` | `1` | `1` |
| 3 Gbit/s | `1` | `1` | `1` | `1` | `1` |
| 5 Gbit/s | `1` | `1` | `1` | `1` | `1` |

In short:

- up to 250 Mbit/s — the strong levels: `4` or `5` on rows and JSON, `7`
  to `9` on HTML, `8` or `9` on JS, `6` on HTTP messages;
- from 300 Mbit/s to 1.5 Gbit/s — `6`, Zstandard 1 as one stream, on rows
  and messages; `7` on HTML; `6` on JSON up to 750 Mbit/s and `2` above;
  on JS `7` or `8` up to 750 Mbit/s and `3` or `6` above;
- from 2 Gbit/s — `1`, and `6` on rows and messages up to 2.5 Gbit/s;
- `0` moves more than `1` only where a link is faster than 5 Gbit/s, or
  where nothing packs.

These are the figures of a busy connection, of batches of 256 KiB. On a
connection of small requests and answers `1` to `5` save little and `6` to
`9` save 1.4 to 4.5 times more — see "Small batches". When the traffic is
paid for, those are the levels to take.

And further:

- These are the figures of an M4 core. On a slower processor every boundary
  moves down: measure on the machine itself, see below.
- When the traffic is paid for and the speed is not what matters, a level
  stronger than the link asks for saves traffic for speed: the tables above
  say how much of each.
- A level costs the sending end one core of each gateway connection at full
  speed, and far less than that on a link which is the limit.
- A level of one stream keeps the stream on both ends for the whole
  connection — see "Small batches" for what that costs.
- A connection which carries nothing but TLS or media gets nothing from any
  level: leave it at `0`.

## Small batches

At the levels `1` to `5` a batch is packed on its own: nothing of the
batches before it is used. So how much they save depends on how much
travels together. The frames of a busy connection go out in big batches; a
lone request on an idle one is a batch of its own, and packs far worse.

At the levels `6` to `9` the batches of a direction are one Zstandard
stream, flushed at the end of every batch: a batch is packed with
everything that went before it — the requests and the answers before it,
the last 0.5 to 4 MiB of them, by the level. A small batch packs nearly as
well as a big one.

The first megabytes of the same samples, cut into batches of a size — the
bytes they take on the wire without compression for a byte they take with
it, the sealing of a frame counted in both:

| data | `compress` | packed with | 256 B | 1 KiB | 4 KiB | 16 KiB | 64 KiB | 256 KiB |
|---|---|---|---|---|---|---|---|---|
| HTTP messages | `1` | LZ4 | 1.02 | 1.25 | 3.13 | 5.17 | 6.36 | 6.59 |
| HTTP messages | `2` | Zstandard 1 | 1.14 | 1.57 | 4.23 | 8.22 | 11.25 | 12.42 |
| HTTP messages | `4` | Zstandard 6 | 1.15 | 1.58 | 4.27 | 8.16 | 10.72 | 12.20 |
| HTTP messages | `6` | Zstandard 1, one stream | 4.02 | 6.94 | 9.25 | 11.91 | 12.55 | 12.69 |
| HTTP messages | `8` | Zstandard 6, one stream | 4.15 | 6.89 | 10.12 | 11.50 | 12.11 | 12.22 |
| API rows | `1` | LZ4 | 1.14 | 1.63 | 1.92 | 2.08 | 2.21 | 2.30 |
| API rows | `2` | Zstandard 1 | 1.32 | 2.34 | 3.36 | 3.83 | 4.06 | 4.07 |
| API rows | `4` | Zstandard 6 | 1.32 | 2.37 | 3.42 | 3.93 | 3.88 | 4.11 |
| API rows | `6` | Zstandard 1, one stream | 2.24 | 3.19 | 3.83 | 4.07 | 4.15 | 4.16 |
| API rows | `8` | Zstandard 6, one stream | 2.24 | 3.28 | 3.77 | 4.00 | 4.05 | 4.06 |
| JSON, repetitive | `1` | LZ4 | 1.38 | 2.35 | 4.39 | 7.96 | 10.13 | 10.76 |
| JSON, repetitive | `2` | Zstandard 1 | 1.59 | 2.93 | 5.93 | 12.10 | 16.97 | 18.82 |
| JSON, repetitive | `4` | Zstandard 6 | 1.60 | 3.03 | 6.41 | 13.15 | 17.76 | 20.39 |
| JSON, repetitive | `6` | Zstandard 1, one stream | 5.20 | 10.39 | 15.10 | 17.88 | 19.28 | 19.61 |
| JSON, repetitive | `8` | Zstandard 6, one stream | 5.19 | 10.32 | 15.70 | 18.82 | 20.18 | 20.48 |
| HTML | `1` | LZ4 | 1.24 | 1.69 | 2.80 | 4.28 | 5.64 | 6.39 |
| HTML | `2` | Zstandard 1 | 1.41 | 2.14 | 3.77 | 6.04 | 8.07 | 9.84 |
| HTML | `4` | Zstandard 6 | 1.42 | 2.21 | 4.08 | 6.85 | 9.50 | 11.98 |
| HTML | `6` | Zstandard 1, one stream | 4.51 | 7.69 | 10.15 | 11.53 | 11.91 | 11.74 |
| HTML | `8` | Zstandard 6, one stream | 5.11 | 9.93 | 13.66 | 15.43 | 16.12 | 16.23 |

- At `1` to `5`, under a kilobyte a level saves a fraction of what it saves
  on big batches, and the levels of Zstandard are one and the same: the
  stronger ones have nothing more to look through.
- At `6` to `9` a request of 256 bytes is 2 to 5 times smaller on the wire,
  and one of a kilobyte 3 to 10 times: 1.4 to 4.5 times less traffic than
  the same Zstandard level sends for it a batch at a time — the least on
  API rows, whose values do not repeat. From 64 KiB on the two kinds save
  about the same, the stream a little more — except where data repeats at
  a distance beyond one batch, HTML here: the stream finds it, a batch on
  its own does not.
- A batch under 64 bytes is not packed by LZ4 and one under 128 bytes not by
  Zstandard on its own; at `6` to `9` one under 32 bytes stays out of the
  stream — a ping, a window update. A small request costs the same time at
  every level: some 27 000 round trips of 100 bytes a second over one
  tunnelled connection and 160 000 over 64 of them, with compression and
  without.
- So what `1` to `5` save on the bill is what they save on the traffic which
  comes in volume; an idle connection of small requests is made cheap by
  `6` to `9` only.

What one stream costs:

- Both ends keep the state of the stream for the whole connection, for
  each direction: the packer on the sending end — 1.3, 3.5, 5.2 and
  15 MiB at `6`, `7`, `8` and `9` — and the unpacker with its window on the
  receiving end — 1, 2.5, 2.5 and 4.5 MiB.
- A batch can no longer be unpacked from itself alone: a piece of the
  stream is unpacked after the ones before it, in their order. A piece
  which does not unpack closes the gateway connection, as any frame which
  is not what a peer sends does; the next connection starts a new stream.
- What does not pack goes into the stream all the same, and costs 3 bytes
  for every 128 KiB.

## What is not in the table

**Stronger Zstandard.** Levels 12, 15 and 19, on batches of 256 KiB — the
packer alone, on one core:

| Zstandard | saves more than level 9 by | MiB/s | a batch of 256 KiB takes |
|---|---|---|---|
| 12 | 1 to 2 % | 29 to 60 | 4 to 9 ms |
| 15 | 5 to 12 % | 12 to 24 | 10 to 21 ms |
| 19 | 5 to 14 % | 6 to 11 | 23 to 40 ms |

A batch is packed by the writer of the gateway connection between two
writes, on a thread of the runtime: the rows of the table are the ones
which take it no more than a few milliseconds a batch. A level which takes
tens of them has to pack on a thread of its own first — and at 256 KiB a
batch it has little left to find.

**Lighter than LZ4.** LZ4 has an acceleration: more of it packs faster and
worse. Through the tunnel, acceleration 4 to 8 is up to 35 % faster than
plain LZ4 and saves 2 to 27 % less; twice the speed takes acceleration 32,
which packs JSON and JS to 1.2 to 1.3 times and no more. Snappy and the
fast levels of Zstandard are about where LZ4 is on big batches — a little
ahead of it on some data, a little behind on other — behind it on small
ones, and unpack up to 3 times slower. Nothing between `0` and `1` is worth
a row.

## How it was measured

```
cargo test --release --bin my-reverse-proxy throughput -- --ignored --nocapture
cargo test --release --bin my-reverse-proxy batch_sizes -- --ignored --nocapture
cargo test --release --bin my-reverse-proxy round_trips -- --ignored --nocapture
```

`throughput` prints, for every sample and level, what the data went as on
the wire and the speed in each direction; `batch_sizes` — what a level
saves by the size of a batch; `round_trips` — what a small request costs.
They make API rows, HTTP messages and bytes which do not pack themselves.
The other samples are files:

```
GATEWAY_BENCH_FILES=/samples/index.json,/samples/docs.html,/samples/bundle.js \
  cargo test --release --bin my-reverse-proxy throughput -- --ignored --nocapture
```

That is also how to measure a sample of the real traffic, and how to get
the figures of the machine a gateway runs on. `GATEWAY_BENCH_ROUNDS` is how
many runs the best is taken of — 3, when it is not set.

A sample has to be megabytes which do not repeat. A block which comes round
again within moments is packed 1.3 to 2 times faster than data ever is —
the processor has learned its way through it — and a benchmark which sends
one block of 256 KiB over and over measures that.
