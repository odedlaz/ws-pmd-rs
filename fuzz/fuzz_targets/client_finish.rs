//! `ClientHandshake::finish` over arbitrary server responses.
//!
//! The offer is fixed and valid, installed and sealed through the public API,
//! so every input exercises the response half against a real client state
//! rather than a synthesised one. Both compositions are driven: a `Conflict`
//! must refuse to produce an agreement no matter what the response says.

#![no_main]

use http::{header::SEC_WEBSOCKET_EXTENSIONS, HeaderMap, HeaderValue};
use libfuzzer_sys::fuzz_target;
use ws_pmd::{ClientConfig, ClientOffer, PmdComposition};

fuzz_target!(|data: &[u8]| {
    // The first byte picks the composition; the rest is the response.
    let (composition, body) = match data.split_first() {
        Some((tag, rest)) if tag % 2 == 0 => (PmdComposition::Compatible, rest),
        Some((_, rest)) => (PmdComposition::Conflict, rest),
        None => return,
    };

    // Neither step reads `data`: a failure is a regression, not a finding.
    // Returning instead made every input a silent success -- with the offer
    // refused this target ran 6.8M iterations green, never reaching `finish`.
    let mut request = HeaderMap::new();
    let offer = ClientOffer::install(ClientConfig::new(), &mut request)
        .expect("the default offer installs into an empty request");
    let handshake = offer.seal(&request).expect("the sealed offer matches the request it wrote");

    let mut response = HeaderMap::new();
    for line in body.split(|b| *b == 0) {
        let Ok(value) = HeaderValue::from_bytes(line) else {
            continue;
        };
        response.append(SEC_WEBSOCKET_EXTENSIONS, value);
    }

    let _ = handshake.finish(&response, composition);
});
