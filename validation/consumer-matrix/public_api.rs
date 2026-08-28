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
    PreparedFinalFragment, PreparedNonFinalFragment, StreamingMessage,
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

// The streaming states cross the same boundary, and for a sharper reason: a host
// that writes a fragment before committing it holds one of these across an
// await, so `!Send` here would not be a missing convenience but an API a runtime
// cannot use. `Sync` is absent for all three, deliberately, as it is above.
const _: () = require_send::<StreamingMessage<'static>>();
const _: () = require_send::<PreparedNonFinalFragment<'static>>();
const _: () = require_send::<PreparedFinalFragment<'static>>();

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

/// A streaming host: it does not have the whole message, and it writes each
/// fragment before saying so.
///
/// The `thread::scope` is standing in for an await. A prepared fragment borrows
/// the encoder, so it cannot be sent to a detached thread at all -- what a real
/// async host does is hold it across a suspension point, and moving it into a
/// scoped thread is the closest a synchronous consumer can come to that. The
/// static assertions above carry the bound; this carries the move.
#[test]
fn a_streaming_host_writes_each_fragment_before_committing_it() {
    let (mut encoder, mut decoder) = codecs();
    let chunks: [&[u8]; 3] = [b"a message the host ", b"never holds ", b"in one piece"];

    let mut wire = Vec::new();
    let mut stream = encoder.begin_streaming_message().expect("a stream");
    for chunk in &chunks[..2] {
        let mut fragment = stream.prepare_non_final_fragment(chunk).expect("a fragment");
        let written = thread::scope(|scope| {
            scope
                .spawn(move || {
                    // The reversible transform a client applies, then the write,
                    // and only then the commit.
                    let mask = [0x5eu8, 0x11, 0xc3, 0x80];
                    for (i, byte) in fragment.as_bytes_mut().iter_mut().enumerate() {
                        *byte ^= mask[i % 4];
                    }
                    let (mut bytes, next) = fragment.commit();
                    for (i, byte) in bytes.iter_mut().enumerate() {
                        *byte ^= mask[i % 4];
                    }
                    (bytes, next)
                })
                .join()
                .expect("the fragment crossed the boundary")
        });
        wire.push(written.0);
        stream = written.1;
    }
    wire.push(stream.prepare_final_fragment(chunks[2]).expect("a final fragment").commit());

    let mut recovered = Vec::new();
    for (i, fragment) in wire.iter().enumerate() {
        recovered.extend_from_slice(
            &decoder.decompress(fragment, i + 1 == wire.len(), ROOMY).expect("decodes"),
        );
    }
    assert_eq!(recovered, chunks.concat(), "the streamed message, fragment by fragment");
    println!("PUBLIC_API=streaming-ok");
}
