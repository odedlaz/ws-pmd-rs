//! `Decoder::decompress` over arbitrary fragment sequences and ceilings.
//!
//! `DecompressedLimit` is a decompression-bomb guard, which makes it the one
//! surface here where an adversarial generator is worth more than a test. The
//! decoder is built through a real client handshake so the agreement under test
//! is one negotiation produced.
//!
//! Two contracts are asserted rather than merely exercised, because a decoder
//! that silently breaks either still returns `Ok`:
//!
//! * the cumulative output of a message never exceeds the ceiling supplied on
//!   the call that produced it, and
//! * the first error poisons the decoder, so every later call fails.

#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use http::{header::SEC_WEBSOCKET_EXTENSIONS, HeaderMap, HeaderValue};
use libfuzzer_sys::fuzz_target;
use ws_pmd::{
    ClientConfig, ClientOffer, CodecError, Decoder, DecompressedLimit, EncoderConfig,
    PmdComposition,
};

/// The plan's ceiling on generated limits: high enough that an ordinary message
/// is not clipped, low enough that a bomb is still bounded inside the run.
const MAX_LIMIT: usize = 1 << 20;
/// The plan's ceiling on one fragment, matching libFuzzer's `-max_len`.
const MAX_FRAGMENT: usize = 64 * 1024;

#[derive(Arbitrary, Debug)]
struct Fragment {
    bytes: Vec<u8>,
    final_fragment: bool,
    limit: usize,
}

fn client_decoder() -> Option<Decoder> {
    let mut request = HeaderMap::new();
    let offer = ClientOffer::install(ClientConfig::new(), &mut request).ok()?;
    let mut response = HeaderMap::new();
    response.append(SEC_WEBSOCKET_EXTENSIONS, HeaderValue::from_static("permessage-deflate"));
    Some(
        offer
            .seal(&request)
            .ok()?
            .finish(&response, PmdComposition::Compatible)
            .ok()??
            .into_codecs(EncoderConfig::new())
            .1,
    )
}

fuzz_target!(|data: &[u8]| {
    let mut unstructured = Unstructured::new(data);
    let Ok(fragments) = Vec::<Fragment>::arbitrary(&mut unstructured) else {
        return;
    };
    let Some(mut decoder) = client_decoder() else {
        return;
    };

    // Mirrors the decoder's own accounting: a non-final fragment adds to the
    // message in progress, a final one ends it.
    let mut delivered = 0usize;
    let mut poisoned = false;

    for fragment in fragments {
        let limit = fragment.limit % (MAX_LIMIT + 1);
        let bytes = &fragment.bytes[..fragment.bytes.len().min(MAX_FRAGMENT)];

        let result =
            decoder.decompress(bytes, fragment.final_fragment, DecompressedLimit::bytes(limit));

        if poisoned {
            assert!(
                matches!(result, Err(CodecError::Poisoned)),
                "a poisoned decoder accepted another fragment"
            );
            continue;
        }

        match result {
            Ok(output) => {
                let total = delivered.saturating_add(output.len());
                assert!(total <= limit, "message reached {total} bytes past a ceiling of {limit}");
                delivered = if fragment.final_fragment { 0 } else { total };
            }
            Err(_) => poisoned = true,
        }
    }
});
