# wtransport 0.7.2 — the CONNECT response survives the handshake

This directory is `wtransport` 0.7.2 as published to crates.io, with one patch
applied. `connect-response.patch` is that patch, and it is the whole difference:
every other file here is byte-identical to the registry copy, which is how it
should stay.

```sh
# Reproduce this directory from scratch
cargo add wtransport@0.7.2                      # or take it out of ~/.cargo/registry
cp -r <registry>/wtransport-0.7.2/src .
patch -p1 < connect-response.patch
```

Each hunk is marked `PATCH:` in the source, so the changed lines are findable
without the diff in hand.

## What it changes

A WebTransport session opens with an HTTP/3 extended CONNECT. The client sends a
request, the server answers with a `:status` and whatever fields it chose, and
upstream `Endpoint::connect` parses that answer, branches on the status, and then
drops it. Nothing downstream can see it.

The patch keeps it, in three places:

- **`connection.rs`** gains `ConnectResponse` — a status and the response's
  fields — and `Connection::connect_response() -> Option<&ConnectResponse>`.
  `None` on a server connection, which sends the response rather than receiving
  one.
- **`endpoint.rs`** builds that value instead of discarding it, and hands it to
  `Connection::new`. It reads the fields off the decoded `Headers` **before**
  the `SessionResponse` conversion, which is the part that is easy to get
  wrong: `impl TryFrom<Headers> for SessionResponse` in `wtransport-proto`
  reads `:status` and then *rebuilds the value from that alone*, so a patch that
  keeps the converted response keeps a map containing one entry. That is not
  visible in a live test — a fleet that all answers `{":status": "200"}` looks
  exactly like a fleet that implements no negotiation — and it is what
  `the_protocol_a_server_selects_comes_back_from_the_connect_response` in
  `moqtap-client` exists to catch.
- **`error.rs`** turns `ConnectingError::SessionRejected` from a unit variant
  into one carrying `status: Option<u16>` and the rejecting response's fields.
  `None` where the peer stopped the request stream before answering at all.
  Its `Display` still begins `server rejected WebTransport session request`, so
  anything matching on that text keeps matching.

The same patch also exposes three accessors upstream keeps private, in
**`error.rs`**: `ConnectionClose::error_code()` and `reason()`, and
`QuicProtoError::code()`. The close codes let a handshake that a peer's
`CONNECTION_CLOSE` ended report that code.

## Why moqtap needs it

MOQT negotiates its version through three channels, and which one is available
depends on the transport. Over QUIC it is the ALPN. Over WebTransport, from
draft-15 on, it is `WT-Available-Protocols` — the client lists the protocol
identifiers it will accept, and the server names its choice in a `WT-Protocol`
response header. That header is in the CONNECT response and nowhere else.

Without it, an accepted WebTransport session says only that *something* in the
offer was agreeable. Reading it back turns drafts 15 on over WebTransport into
the same exclusion loop the ALPN already gets over QUIC: offer everything
remaining, remove what came back, repeat until the server refuses.

The rejection status is the same fact from the other side. A server that reads
an offer and refuses it answers about a *draft*; one that 404s answers about a
path. Both used to arrive as the same empty variant.

## Its status

Local, deliberately, and intended for upstream. Until it is upstream:

- `moqtap-client` may only reach this API behind its `wt-protocol` feature,
  which is off by default and documented as requiring this directory. A
  `[patch]` section applies to the workspace being built and is **not** carried
  into a published crate, so unconditional use here would compile locally and
  break for every consumer of `moqtap-client` on crates.io.
- Every top-level manifest that wants the patch needs its own
  `[patch.crates-io]` pointing here, since a `[patch]` section is not inherited
  through a path dependency. This workspace's `Cargo.toml` carries one.

If upstream takes it, all of that goes away and the `wt-protocol` feature
becomes a version bump.

## Licence

`wtransport` is MIT OR Apache-2.0, by Biagio Festa —
<https://github.com/BiagioFesta/wtransport>. Vendoring it does not change that;
the copy here carries the same terms as the original, and the patch above is
offered on the same.
