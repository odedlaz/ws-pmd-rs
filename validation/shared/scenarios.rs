// Shared scenario source for both named backend arms, `include!`d rather than
// made into a crate: one copy so the arms cannot drift, and no crate that could
// be built with the other arm's backend.
//
// Payload and protocol are the frozen far-reference reproducer's
// (`RESEARCH/PMD_FAR_REFERENCE_REPRODUCER_2026_08_23/`). What differs here is the
// driver: these go through the crate's public `Decoder`, which is chunked at its
// own `SCRATCH`, rather than through `flate2` directly.

use flate2::{Compress, Compression, Decompress, FlushCompress, FlushDecompress, Status};
use http::{header::SEC_WEBSOCKET_EXTENSIONS, HeaderMap, HeaderValue};
use ws_pmd::{
    ClientConfig, ClientOffer, CodecError, Decoder, DecompressedLimit, EncoderConfig,
    PmdComposition,
};

const TRAILER: &[u8] = &[0x00, 0x00, 0xff, 0xff];
const ROOMY: DecompressedLimit = DecompressedLimit::bytes(1 << 22);

/// What the crate's public decoder did with a message.
#[derive(Debug, PartialEq, Eq)]
enum Outcome {
    /// Decoded, and byte-exact against the plaintext the peer compressed.
    Exact,
    Wrong(String),
    /// Carrying the cause, because `Stalled`, `Poisoned` and a limit overrun are
    /// all rejections too, and none of them is window enforcement.
    Rejected(CodecError),
}

/// The reproducer's generator, unchanged, so both arms see identical bytes.
fn rnd(n: usize, seed: u32) -> Vec<u8> {
    let mut s = seed | 1;
    let mut v = Vec::with_capacity(n + 4);
    while v.len() < n {
        s ^= s << 13;
        s ^= s >> 17;
        s ^= s << 5;
        v.extend_from_slice(&s.to_le_bytes());
    }
    v.truncate(n);
    v
}

/// 4 KiB of random bytes, `gap - 4096` of filler, then the same 4 KiB again. The
/// repeat is a match only if the window reaches back `gap`, and 4 KiB of match is
/// unmistakable in the wire size rather than a difference anyone must interpret.
fn far_reference_payload(gap: usize) -> Vec<u8> {
    assert!(
        gap >= 4096,
        "gap {gap} is under the marker length, so the distance would be 4096 whatever was asked \
         for -- the precondition is enforced here rather than documented, because a silent \
         clamp is what made a boundary row prove a different boundary"
    );
    let repeated = rnd(4096, 0xABCD);
    let mut plain = repeated.clone();
    plain.extend_from_slice(&rnd(gap - 4096, 0x1234));
    plain.extend_from_slice(&repeated);
    plain
}

/// One RFC 7692 message from a peer that compressed at `window_bits` whatever it
/// declared: raw DEFLATE, `Z_SYNC_FLUSH`, trailer stripped.
///
/// The flush has to be looped: one `compress_vec` call writes only into the
/// vector's spare capacity, so a single call silently emits a partial flush and
/// truncates the message. The trailer assertion is what catches that.
fn peer_message(plain: &[u8], window_bits: u8) -> Vec<u8> {
    let mut peer = Compress::new_with_window_bits(Compression::best(), false, window_bits);
    let mut wire = Vec::new();
    let mut input = plain;
    while !input.is_empty() {
        wire.reserve(4096);
        let before = (peer.total_in(), peer.total_out());
        peer.compress_vec(input, &mut wire, FlushCompress::None).expect("peer compresses");
        let consumed = usize::try_from(peer.total_in() - before.0).expect("fits");
        if consumed == 0 && peer.total_out() == before.1 {
            break;
        }
        input = &input[consumed..];
    }
    loop {
        wire.reserve(4096);
        let before = peer.total_out();
        peer.compress_vec(&[], &mut wire, FlushCompress::Sync).expect("peer flushes");
        if peer.total_out() == before {
            break;
        }
    }
    assert!(wire.ends_with(TRAILER), "the peer must emit a sync-flush trailer");
    assert!(input.is_empty(), "the whole payload must reach the wire");
    wire.truncate(wire.len() - TRAILER.len());
    wire
}

/// One conforming message from a peer that flushed with `BFINAL` set, which is
/// what drives the decoder's recovery reinitialisation.
///
/// RFC 7692 section 7.2.3.4 permits the flush; section 7.2.1 still applies to the
/// message. Step 2 appends an empty `BTYPE=00` block after the padded `BFINAL`
/// block and step 3 removes its four octets, leaving the single `0x00` that
/// section 7.2.3.4 calls necessary. A bare `Finish` stream without it is
/// malformed input, not a `BFINAL` message, and the crate rejects it -- which
/// would satisfy every rejection row below for the wrong reason.
fn bfinal_message(plain: &[u8], window_bits: u8) -> Vec<u8> {
    let mut peer = Compress::new_with_window_bits(Compression::best(), false, window_bits);
    let mut wire = vec![0u8; plain.len() * 2 + 1024];
    let status = peer.compress(plain, &mut wire, FlushCompress::Finish).expect("one buffer");
    assert_eq!(status, Status::StreamEnd, "the whole stream must finish in one buffer");
    wire.truncate(usize::try_from(peer.total_out()).expect("fits"));
    wire.push(0x00);
    wire
}

/// A client decoder for the response a server sent, so the agreement under test
/// is one the crate's own negotiation produced.
fn decoder_for(response: &str) -> Decoder {
    let mut request = HeaderMap::new();
    let offer = ClientOffer::install(ClientConfig::new(), &mut request).expect("fresh map");
    let mut headers = HeaderMap::new();
    headers.append(
        SEC_WEBSOCKET_EXTENSIONS,
        HeaderValue::from_str(response).expect("a valid header value"),
    );
    offer
        .seal(&request)
        .expect("the offer is unchanged")
        .finish(&headers, PmdComposition::Compatible)
        .expect("the response is legal")
        .expect("the server selected it")
        .into_codecs(EncoderConfig::new())
        .1
}

fn feed(decoder: &mut Decoder, wire: &[u8], expected: &[u8]) -> Outcome {
    match decoder.decompress(wire, true, ROOMY) {
        Ok(bytes) if bytes == expected => Outcome::Exact,
        Ok(bytes) => {
            Outcome::Wrong(format!("{} bytes, not the {} sent", bytes.len(), expected.len()))
        }
        Err(error) => Outcome::Rejected(error),
    }
}

/// A fresh decoder at `declared`, handed a message compressed at 15.
fn fresh(declared: u8, gap: usize) -> Outcome {
    let plain = far_reference_payload(gap);
    let wire = peer_message(&plain, 15);
    feed(
        &mut decoder_for(&format!("permessage-deflate; server_max_window_bits={declared}")),
        &wire,
        &plain,
    )
}

/// The same, but after the no-context-takeover reinitialisation has run: one
/// conforming message first, so the inflater under test is the reinitialised one.
fn after_no_context_reinit(declared: u8, gap: usize) -> Outcome {
    let mut decoder = decoder_for(&format!(
        "permessage-deflate; server_no_context_takeover; server_max_window_bits={declared}"
    ));
    let first = b"conforming first message, well within any window";
    assert_eq!(
        feed(&mut decoder, &peer_message(first, declared), first),
        Outcome::Exact,
        "the conforming first message must decode in both arms"
    );
    let plain = far_reference_payload(gap);
    feed(&mut decoder, &peer_message(&plain, 15), &plain)
}

/// The same, after the `BFINAL` recovery reinitialisation has run.
fn after_bfinal_reinit(declared: u8, gap: usize) -> Outcome {
    let mut decoder =
        decoder_for(&format!("permessage-deflate; server_max_window_bits={declared}"));
    let first = b"a peer that ends its stream must start a new one";
    assert_eq!(
        feed(&mut decoder, &bfinal_message(first, declared), first),
        Outcome::Exact,
        "the BFINAL first message must decode in both arms"
    );
    let plain = far_reference_payload(gap);
    feed(&mut decoder, &peer_message(&plain, 15), &plain)
}

/// Presence of the far match, proven by wire size rather than assumed: a 4 KiB
/// match is worth thousands of bytes, which no Huffman-table difference is.
fn far_match_saving(gap: usize) -> usize {
    let plain = far_reference_payload(gap);
    peer_message(&plain, 9).len().saturating_sub(peer_message(&plain, 15).len())
}

/// Every stream start where `flate2` produced output without consuming input, or
/// produced nothing at all.
///
/// The crate's `stream_open` widening is classified equivalent only while a
/// stream start cannot produce before it consumes. `src/codec.rs` asserts that on
/// the backend the library resolves; this is the other supported graph, and the
/// arms are the only place it runs. Reached through `flate2` directly, because
/// the public decoder reports what a message decoded to and not what one backend
/// call moved -- so a divergence here is invisible to every other row.
///
/// A case that produced nothing is reported too: it would satisfy the premise
/// while measuring nothing.
fn stream_starts_that_broke_the_premise() -> Vec<String> {
    let wire = bfinal_message(b"hello, hello, hello", 15);
    let mut broken = Vec::new();
    for window_bits in 9..=15u8 {
        for width in [1usize, 2, 4096] {
            let mut inflater = Decompress::new_with_window_bits(false, window_bits);
            let mut scratch = vec![0u8; width];
            inflater
                .decompress(&wire, &mut scratch, FlushDecompress::None)
                .expect("the wire decodes");
            let at = format!("window {window_bits}, scratch {width}");
            if inflater.total_out() == 0 {
                broken.push(format!("{at}: produced nothing, so it measures nothing"));
            } else if inflater.total_in() == 0 {
                broken
                    .push(format!("{at}: produced {} with nothing consumed", inflater.total_out()));
            }
        }
    }
    broken
}
