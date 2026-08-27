//! What a host can build from the published surface, from outside the package.
//!
//! Compiled against the unpacked `.crate` in every backend graph, so it sees the
//! same items a consumer sees: no private modules, no `validation/` sources, and
//! nothing this crate does not export.
//!
//! It is not a conformance oracle and must never be read as one. Where a message
//! goes through this crate's encoder and back through its decoder, that proves
//! ownership and compilation, not correctness -- two matching mistakes in one
//! implementation's own halves look exactly like a round trip. Conformance is the
//! arms' business, against a direct `flate2` peer.

use std::thread;

use http::{header::SEC_WEBSOCKET_EXTENSIONS, HeaderMap, HeaderValue};
use ws_pmd::{
    ClientConfig, ClientOffer, Decoder, DecompressedLimit, Encoder, EncoderConfig, PmdComposition,
};

const ROOMY: DecompressedLimit = DecompressedLimit::bytes(1 << 20);

/// The property `into_codecs` exists for, from a consumer's position.
///
/// A host puts the two halves in the two tasks that own them, so each must cross
/// a task boundary. `Sync` is deliberately absent: nothing needs shared access to
/// either half, and asserting it here would commit the crate to it.
const fn require_send<T: Send>() {}
const _: () = require_send::<Encoder>();
const _: () = require_send::<Decoder>();

/// An agreement built by running the real handshake, because there is no other
/// way in -- local configuration cannot be turned into a codec directly.
fn codecs() -> (Encoder, Decoder) {
    let mut request = HeaderMap::new();
    let offer = ClientOffer::install(ClientConfig::new(), &mut request).expect("a fresh map");
    let mut response = HeaderMap::new();
    response.append(SEC_WEBSOCKET_EXTENSIONS, HeaderValue::from_static("permessage-deflate"));
    offer
        .seal(&request)
        .expect("the offer is unchanged")
        .finish(&response, PmdComposition::Compatible)
        .expect("the response is legal")
        .expect("the server selected it")
        .into_codecs(EncoderConfig::new())
}

/// A receive-only host: it drops the encoder and pays one compressor for it.
///
/// This is the shape that used to have its own constructor. Dropping half a pair
/// has to be ordinary, or the single terminal constructor is a tax rather than a
/// simplification.
#[test]
fn a_receive_only_host_discards_the_encoder() {
    let (encoder, mut decoder) = codecs();
    drop(encoder);

    // Still a working decoder afterwards, driven only through the public API.
    let (mut peer, _) = codecs();
    let message = peer.prepare_message(b"receive only").expect("prepared").commit();
    assert_eq!(
        decoder.decompress(&message, true, ROOMY).expect("decodes"),
        b"receive only",
        "the surviving half must still work"
    );
    println!("PUBLIC_API=receive-only-ok");
}

/// A bidirectional host: the halves go to different threads and neither waits on
/// the other.
///
/// Threads rather than a static assertion alone, because the assertion proves the
/// bound and this proves the move. A `!Send` field added later fails both, and a
/// host that cannot actually split the pair fails only this.
#[test]
fn a_bidirectional_host_splits_the_pair_across_threads() {
    let (mut encoder, mut decoder) = codecs();
    let payload = b"a message that leaves one task and arrives in another".to_vec();

    let sent = payload.clone();
    let writer = thread::spawn(move || {
        // Prepare, apply a reversible transport transform the way a client masks,
        // then declare it sent.
        let mut prepared = encoder.prepare_message(&sent).expect("prepared");
        let mask = [0x9au8, 0x21, 0x4c, 0x07];
        for (i, byte) in prepared.as_bytes_mut().iter_mut().enumerate() {
            *byte ^= mask[i % 4];
        }
        let mut wire = prepared.commit();
        for (i, byte) in wire.iter_mut().enumerate() {
            *byte ^= mask[i % 4];
        }

        // And the other resolution: a candidate that never reaches the wire.
        encoder.prepare_message(b"never sent").expect("prepared").reset_to_plain();
        let after = encoder.prepare_message(b"after the reset").expect("prepared").commit();
        (wire, after)
    });
    let (first, second) = writer.join().expect("the writer half moved and ran");

    let reader = thread::spawn(move || {
        let one = decoder.decompress(&first, true, ROOMY).expect("first decodes");
        let two = decoder.decompress(&second, true, ROOMY).expect("second decodes");
        (one, two)
    });
    let (one, two) = reader.join().expect("the reader half moved and ran");

    assert_eq!(one, payload, "the masked-and-unmasked message");
    assert_eq!(two, b"after the reset", "the message after a discarded candidate");
    println!("PUBLIC_API=bidirectional-ok");
}
