//! `ServerHandshake::accept` over arbitrary `Sec-WebSocket-Extensions` fields.
//!
//! The public entry point drives the private grammar, so no parser seam is
//! exposed for the harness. Errors and declines are outcomes, not findings:
//! a malformed field *must* produce `MalformedHeader`, and an extension this
//! crate does not implement *must* produce `Ok(None)`. Only a panic, an abort,
//! or unbounded allocation is a failure.

#![no_main]

use http::{header::SEC_WEBSOCKET_EXTENSIONS, HeaderMap, HeaderValue};
use libfuzzer_sys::fuzz_target;
use ws_pmd::{ServerConfig, ServerHandshake};

fuzz_target!(|data: &[u8]| {
    let mut headers = HeaderMap::new();
    // One field line per NUL, so the corpus can reach the multi-line and
    // repeated-header paths that a single value cannot.
    for line in data.split(|b| *b == 0) {
        let Ok(value) = HeaderValue::from_bytes(line) else {
            continue;
        };
        headers.append(SEC_WEBSOCKET_EXTENSIONS, value);
    }

    if let Ok(Some(handshake)) = ServerHandshake::accept(ServerConfig::new(), &headers) {
        let _ = handshake.value();
    }
});
