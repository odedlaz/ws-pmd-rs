# ws-pmd

RFC 7692 `permessage-deflate` for Rust: extension negotiation and per-connection DEFLATE
state, independent of any WebSocket implementation.

This crate owns two things — whether the extension was correctly negotiated, and the
compression state that follows from the agreement. It owns nothing else. It has no socket,
no runtime, and no frame type, and it holds no opinion about masking, opcodes, close codes,
UTF-8, or message assembly. Those stay with the host.

The crate is `ws-pmd`; its repository is `ws-pmd-rs`. Where this document writes
`permessage-deflate` it means the RFC 7692 extension token, not the crate.

## Status

Version 0.1.0, unreleased. It is not published to crates.io. The public API is the
smallest surface that serves the target integrations, and it may change before 1.0 as
those integrations land.

Until it is published, depend on it by git reference:

```toml
[dependencies]
ws-pmd = { git = "https://github.com/odedlaz/ws-pmd-rs" }
```

## Scope

| this crate | the host |
|---|---|
| `Sec-WebSocket-Extensions` against the RFC 6455 §9.1 grammar | sockets, TLS, the async runtime |
| choosing and committing an offer or a selection, both roles | framing, fragmentation, and the RSV1 bit in both directions |
| the negotiated windows and no-context-takeover behaviour | masking |
| the DEFLATE compressor and inflater for one connection | message assembly and control-frame routing |
| the RFC 7692 §7.2.1 trailer, on both sides | close codes and UTF-8 validation |
| a ceiling on the bytes one message may decompress to | which other extensions were selected |

The last row is a handshake argument, not an inference. The crate cannot see the other
extensions a connection selected, so the host states whether they compose with
`permessage-deflate`, and the signature makes that statement mandatory.

## Handshake

Both roles are state machines whose types enforce their order, so compression state cannot
be built from anything but a finalized agreement.

A client installs its offer, seals it against the request that is actually being sent, then
applies the response:

```rust
use http::HeaderMap;
use ws_pmd::{ClientConfig, ClientOffer, PmdComposition};

let mut request = HeaderMap::new();
let offer = ClientOffer::install(ClientConfig::new(), &mut request)?;

// The host finishes building the request, then seals at the send boundary.
let handshake = offer.seal(&request)?;

// ... send the request, read the response ...
let Some(negotiated) = handshake.finish(&response, PmdComposition::Compatible)? else {
    // The server declined. Carry on uncompressed; this is not an error.
    return Ok(());
};
```

A server takes the first alternative it can support, hands the host the exact response
element, and commits only once that element has survived the host's own callbacks:

```rust
use http::{header::SEC_WEBSOCKET_EXTENSIONS, HeaderMap};
use ws_pmd::{PmdComposition, ServerConfig, ServerHandshake};

let Some(selection) = ServerHandshake::accept(ServerConfig::new(), &request)? else {
    // Nothing offered, or nothing this configuration can honour.
    return Ok(());
};

let mut response = HeaderMap::new();
response.insert(SEC_WEBSOCKET_EXTENSIONS, selection.value().clone());

// ... the host runs its own callbacks over the response ...
let Some(negotiated) = selection.finish(&response, PmdComposition::Compatible)? else {
    // A callback removed the extension. The host changed its mind, which is allowed.
    return Ok(());
};
```

`Ok(None)` is a decline and leaves the connection uncompressed, which is always a legal
outcome. An `Err` is a different thing: a `NegotiationError::MalformedHeader` means the peer
broke the header grammar and RFC 6455 §9.1 requires the host to fail the opening handshake.
Do not handle it as a decline.

A client that deliberately offers nothing seals that fact instead, with
`ClientHandshake::seal_without_offer`, and gets an error rather than an agreement if the
server selects `permessage-deflate` anyway. Only the client can see that violation, so
without this entry point the rule would fall to every host separately.

## Codecs

An agreement is consumed to produce the pair of codecs for that connection. `Negotiated` is
neither `Copy` nor `Clone`, so one agreement cannot mint two sets of compression state.

```rust
use ws_pmd::{DecompressedLimit, EncoderConfig};

let (mut encoder, mut decoder) = negotiated.into_codecs(EncoderConfig::new());

// Sending: compress the complete message, frame the bytes yourself with RSV1 set on
// the first frame only, then declare that they reached the wire.
let prepared = encoder.prepare_message(payload)?;
transport.write_all(prepared.as_bytes())?;
let compressed = prepared.commit();

// Receiving: pass each fragment's payload in order, marking the last one.
let message = decoder.decompress(fragment, is_final, DecompressedLimit::bytes(1 << 20))?;
```

Two things about the sending side are easy to miss, and both are deliberate.

RFC 7692 §7.2.1 permits two ways to build fragments: split the result of compressing the
whole message, or build each fragment from the payload available so far. `prepare_message`
implements the first, so it takes a whole message and the host splits the result into
frames. `begin_streaming_message` implements the second, for a host that does not have the
whole message:

```rust
use ws_pmd::EncoderConfig;

let (mut encoder, _decoder) = negotiated.into_codecs(EncoderConfig::new());
let mut stream = encoder.begin_streaming_message()?;

// One frame per chunk. RSV1 on the first, FIN on none of them.
for chunk in chunks {
    let fragment = stream.prepare_non_final_fragment(chunk)?;
    transport.write_all(fragment.as_bytes())?;
    let (bytes, next) = fragment.commit();
    stream = next;
}

// The last frame carries FIN, and only here is the trailer removed.
let last = stream.prepare_final_fragment(tail)?;
transport.write_all(last.as_bytes())?;
let bytes = last.commit();
```

The two differ on the wire and in what they cost. A non-final fragment keeps every
`00 00 ff ff` its flush produced — removing it is what §7.2.1 forbids there — while the final
one has exactly the terminal four octets removed, or is the single `0x00` octet if the
message produced nothing. Each fragment ends in a sync flush, so streaming a message in many
small pieces compresses it less well than handing over the whole thing; use
`prepare_message` whenever the message is already in memory. An empty non-final chunk is a
legal boundary and may return no bytes at all, after an earlier fragment has already flushed.

`PreparedMessage` is a transaction. Preparing a message moves the compressor out of the
encoder and into the guard, so a candidate that may never reach the wire cannot quietly
advance this side's compression history. Calling `commit` returns the advanced history;
`reset_to_plain` says the bytes will not be sent and starts the history over, and the host
sends its original payload with RSV1 clear. Every other outcome — an error, a dropped
guard, a cancelled write — leaves the encoder poisoned, because a host whose write was
cancelled after an unknown number of octets cannot know what the peer received.

The streaming states are the same transaction, one fragment at a time, with one difference:
there is no `reset_to_plain`. Once a fragment has committed its octets are on the wire and
the peer has inflated them, so the message cannot be re-sent uncompressed; an exit that
stopped working part-way through a message would be worse than none.

`DecompressedLimit` has no unbounded spelling. Compressed input is the one path where a
small frame can ask for arbitrary memory, so a host whose plain-message setting is unbounded
still supplies a finite ceiling here. It bounds the decompressed bytes of one message across
all its fragments, and it is separate from whatever guard the host keeps on compressed input.

The receiving side owes three things this crate cannot do for you, because it never sees a
frame:

- **Route on RSV1, and only on RSV1.** RFC 7692 §6.2 defines two receive algorithms, and the
  bit on a message's first frame picks between them. A message that arrived with RSV1 clear
  goes to the application as it is; passing it to `decompress` instead is the easiest wrong
  call in this API, and the signature takes bytes and no bit, so nothing here can catch it.
- **Fail the connection on RSV1 where the RFC forbids it.** RFC 7692 §6 puts this on the
  receiver and not only on the sender:

  > An endpoint MUST NOT set the "Per-Message Compressed" bit of control frames and
  > non-first fragments of a data message.  An endpoint receiving such a frame MUST _Fail
  > the WebSocket Connection_.

- **Fail the connection on a reserved bit nothing defines.** RFC 6455 §5.2 requires it of any
  nonzero RSV bit no negotiated extension gives a meaning to. `permessage-deflate` gives RSV1
  a meaning once it has been agreed, and gives RSV2 and RSV3 none ever.

Sending is the mirror of the first two: RSV1 on the first frame of a compressed message, and
on nothing else.

## Backends

Compression comes from [`flate2`](https://crates.io/crates/flate2). Two features forward a
backend choice:

| feature | forwards |
|---|---|
| `zlib-rs` (default) | `flate2/zlib-rs` |
| `zlib` | `flate2/zlib` |

**These are activation requests, not exclusive guarantees.** Cargo unions features across a
dependency graph, so naming one here cannot stop another crate in your graph from enabling
the other. What they buy is the ability to switch the default off and choose. Selecting
neither is legal when some other edge supplies a backend, and `flate2` raises its own error
when none does.

Which backend a graph resolved is visible in `cargo tree -e features`, not in behaviour: the
two implement one specification. Where they diverge is inflater window enforcement, and the
repository's `validation/` pins both sides of it. Compressed output is not byte-identical
between them, so any measurement of size or speed must name the backend, the compression level
and the platform to mean anything.

## Correctness

The crate forbids `unsafe` and denies panicking constructs in production code: every site
that could panic, index, or exit out of band carries an allowance with the invariant named
and a test pinning it, so the allowance goes red if the invariant stops holding.

The decoder's tests drive it from a `flate2` peer independent of this crate's encoder, so a
mistake shared by both cannot pass as a round trip. That peer is the same engine the crate
itself calls, so it checks this crate's codec logic and not DEFLATE. Beyond the crate's own
suite, the repository's `validation/` holds two named-backend arms and a consumer matrix that
builds the *packaged* crate from outside. See
[`validation/README.md`](https://github.com/odedlaz/ws-pmd-rs/blob/main/validation/README.md).

The suite tests RFC 7692 byte vectors. There is no published Autobahn or other
conformance-suite run for this crate.

## Minimum supported Rust version

Rust 1.85, edition 2021. Raising it is a breaking change.

## Getting help and contributing

Bug reports and patches go through the repository's issue tracker. See
[CONTRIBUTING.md](https://github.com/odedlaz/ws-pmd-rs/blob/main/CONTRIBUTING.md) for the
scope this crate accepts and the gate a change has to pass.

## Acknowledgements

Portions of this crate's `Sec-WebSocket-Extensions` grammar, RFC 7692 negotiation, DEFLATE
codec, and test fixtures derive from the `permessage-deflate` work in tungstenite-rs —
authored by Alex Bakon based on work by Benjamin Swart — as carried in
[Signal's fork](https://github.com/signalapp/tungstenite-rs).

tungstenite-rs is available under MIT OR Apache-2.0. This crate uses it under MIT and
retains its copyright notices in [LICENSE](LICENSE).

## License

MIT. See [LICENSE](LICENSE).
