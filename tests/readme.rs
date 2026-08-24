//! Compiles the README's Rust blocks, and pins them to the README.
//!
//! Each block appears exactly once in this file: as the body of a wrapper below, which is
//! the copy the compiler checks. `every_readme_rust_block_is_pinned` then requires every
//! fenced `rust` block in the README to appear verbatim in this file's own source, so a
//! README edit that is not mirrored here turns the suite red rather than going unnoticed.
//!
//! Two limits on what that buys, both deliberate.
//!
//! It says nothing about whether an example is *correct* -- only that it compiles, and that
//! the README still says what compiles.
//!
//! It is scoped to `rust` fences, so the README's `toml` dependency block is outside the
//! pin. That is not an oversight to correct: the block states how to depend on an
//! unpublished crate, so it is expected to change on its own schedule, and pinning it would
//! turn this test red at the next version bump for a reason nobody would connect to it.
//! Adding a `toml` fence leaves the count alone; converting one to `rust` does not.
//!
//! And it is a *text* instrument. It proves the README's blocks appear here; the compiler
//! proves that what is not commented out compiles. Those are two facts, and a `/* */` around
//! a body separates them -- the bytes stay byte-identical, the pin stays green, and nothing
//! type-checks. Delimiting the bodies with markers and matching the region does not close
//! that: a `/* */` placed around the markers themselves passes just as green. Both of those
//! were measured.
//!
//! The general form is scoped to *byte-verbatim* matching: any boundary such a comparison can
//! draw is enclosable the same way, because a byte comparison cannot tell code from a comment
//! holding the same bytes. A token-level pin would not share that weakness -- comments are not
//! tokens -- but that is reasoning, not a measurement, and it is deliberately not pursued. It
//! buys resistance to tamper, which the paragraph below puts out of scope, and pays by
//! comparing normalised tokens rather than the README's actual bytes.
//!
//! That is a limit, not a hole to engineer around. Every *accidental* edit is caught --
//! changing a body, changing the README, commenting a body out line by line. Wrapping a body
//! in a block comment is deliberate, lands in a diff someone reads, and is the same class as
//! deleting this file.
//!
//! The bodies sit at column 0 and the wrappers are `#[rustfmt::skip]`, because the pin is a
//! byte comparison and any reindentation would break it.
// One signature serves all three blocks, so every wrapper takes all seven bindings and
// each block shadows or ignores the ones it does not use. That is the point, not an
// oversight -- a per-block signature would be three preambles to keep in step.
#![allow(unused_variables, unused_imports, unused_mut, clippy::needless_pass_by_value)]

use std::error::Error;
use std::io::Write;

use http::HeaderMap;
use permessage_deflate::Negotiated;

const README: &str = include_str!("../README.md");
const SELF: &str = include_str!("readme.rs");

#[rustfmt::skip]
fn client(
    request: HeaderMap,
    response: HeaderMap,
    negotiated: Negotiated,
    payload: &[u8],
    fragment: &[u8],
    is_final: bool,
    transport: &mut dyn Write,
) -> Result<(), Box<dyn Error>> {
use http::HeaderMap;
use permessage_deflate::{ClientConfig, ClientOffer, PmdComposition};

let mut request = HeaderMap::new();
let offer = ClientOffer::install(ClientConfig::new(), &mut request)?;

// The host finishes building the request, then seals at the send boundary.
let handshake = offer.seal(&request)?;

// ... send the request, read the response ...
let Some(negotiated) = handshake.finish(&response, PmdComposition::Compatible)? else {
    // The server declined. Carry on uncompressed; this is not an error.
    return Ok(());
};
Ok(())
}

#[rustfmt::skip]
fn server(
    request: HeaderMap,
    response: HeaderMap,
    negotiated: Negotiated,
    payload: &[u8],
    fragment: &[u8],
    is_final: bool,
    transport: &mut dyn Write,
) -> Result<(), Box<dyn Error>> {
use http::{header::SEC_WEBSOCKET_EXTENSIONS, HeaderMap};
use permessage_deflate::{PmdComposition, ServerConfig, ServerHandshake};

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
Ok(())
}

#[rustfmt::skip]
fn codecs(
    request: HeaderMap,
    response: HeaderMap,
    negotiated: Negotiated,
    payload: &[u8],
    fragment: &[u8],
    is_final: bool,
    transport: &mut dyn Write,
) -> Result<(), Box<dyn Error>> {
use permessage_deflate::{DecompressedLimit, EncoderConfig};

let (mut encoder, mut decoder) = negotiated.into_codecs(EncoderConfig::new());

// Sending: compress the complete message, frame the bytes yourself with RSV1 set on
// the first frame only, then declare that they reached the wire.
let prepared = encoder.prepare_message(payload)?;
transport.write_all(prepared.as_bytes())?;
let compressed = prepared.commit();

// Receiving: pass each fragment's payload in order, marking the last one.
let message = decoder.decompress(fragment, is_final, DecompressedLimit::bytes(1 << 20))?;
Ok(())
}

fn readme_rust_blocks() -> Vec<&'static str> {
    README
        .split("```rust\n")
        .skip(1)
        .filter_map(|rest| rest.split_once("\n```"))
        .map(|(block, _)| block)
        .collect()
}

#[test]
fn every_readme_rust_block_is_pinned() {
    let blocks = readme_rust_blocks();
    assert_eq!(blocks.len(), 3, "a rust block was added to or removed from the README");
    for (i, block) in blocks.iter().enumerate() {
        assert!(SELF.contains(block), "README rust block {i} is not pinned in this file");
    }
    let _ = (client, server, codecs);
}
