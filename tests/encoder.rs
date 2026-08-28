//! The encoder, driven through the public API only.
//!
//! Every compressed result here is decoded by an inflater built directly on
//! `flate2`, never by this crate's `Decoder`: a round trip through one
//! implementation's own two halves cannot tell a correct codec from two matching
//! mistakes. The byte-exact expectations come from RFC 7692's own worked
//! examples, which were published in 2015 and owe nothing to `flate2` or to us.
#![expect(clippy::expect_used, clippy::indexing_slicing, reason = "a panic is how a test reports")]

use flate2::{Compress, Compression, Decompress, FlushCompress, FlushDecompress, Status};
use http::{header::SEC_WEBSOCKET_EXTENSIONS, HeaderMap, HeaderValue};
use ws_pmd::{
    ClientConfig, ClientOffer, CodecError, Decoder, DecompressedLimit, Encoder, EncoderConfig,
    PmdComposition, PreparedFinalFragment, PreparedNonFinalFragment, ServerConfig, ServerHandshake,
    StreamingMessage,
};

/// RFC 7692 section 7.2.1 step 3 removes this from every message's tail, so a
/// verifier has to put it back before the message can end.
const TRAILER: &[u8] = &[0x00, 0x00, 0xff, 0xff];

/// RFC 7692 section 7.2.3.6: the payload of a message that compresses to
/// nothing.
const EMPTY_MESSAGE: &[u8] = &[0x00];

/// The property the split pair exists for, from a consumer's position.
///
/// `into_codecs` hands back two owners so a host can move each direction into
/// the task that owns it, which for a runtime like tokio-websockets means two
/// tasks -- so the property is `Send`. Both halves satisfy it today only because
/// `flate2::Compress` and `Decompress` do; a future field that quietly did not
/// would fail here rather than in some host's adapter.
///
/// `Sync` is deliberately not asserted. Nothing needs it, and promising it would
/// be a semver commitment bought for nothing.
///
/// Called from a test rather than a `const _: () = require_send::<T>()`, which
/// 1.85 -- the declared MSRV -- reads as dead code. Both forms are compile-time
/// checks, so this fails the build, not the run, if a codec stops being `Send`.
const fn require_send<T: Send>() {}

#[test]
fn both_codecs_are_send() {
    require_send::<Encoder>();
    require_send::<Decoder>();
}

// ---------------------------------------------------------------- the oracles

/// A peer inflater built straight on `flate2`.
///
/// Independent of this crate's `Decoder` and therefore of our reading of RFC
/// 7692 — which is the failure this oracle exists to catch. It is *not*
/// independent of `flate2`: inside one arm the compressor under test and this
/// inflater are the same implementation, so a self-consistent backend defect
/// cancels silently. DEFLATE-layer independence comes only from the two arms
/// being separate implementations that both accept the transform; transform-
/// layer independence comes from the RFC vectors below.
struct Verifier(Decompress);

impl Verifier {
    fn new() -> Self {
        // Always 15. A wider inflater accepts every stream a narrower
        // compressor can emit, so one verifier serves every negotiated width.
        Self(Decompress::new_with_window_bits(false, 15))
    }

    /// One complete message's wire bytes, with the stripped trailer fed back.
    ///
    /// A whole-message candidate and a streamed message's fragments concatenated
    /// in order are the same input here: one message loses exactly one trailer,
    /// wherever it was produced, so the feed-back is the same either way.
    ///
    /// The message must also be *read*, not merely decoded. RFC 7692's tail is
    /// an empty **non-final** stored block, so a conforming message leaves this
    /// inflater open and waiting; `StreamEnd` means some block claimed to be the
    /// last and whatever followed it was never looked at. Returning the
    /// plaintext and stopping there accepts exactly that, which is a peer that
    /// agrees with a producer it never finished reading --
    /// `gate-peer-oracle` is the row that fails without the `StreamEnd` refusal.
    /// The second refusal below is not pinned by any row; its own comment says
    /// why it is kept anyway.
    fn accept(&mut self, wire: &[u8]) -> Result<Vec<u8>, String> {
        let mut fed = wire.to_vec();
        fed.extend_from_slice(TRAILER);
        let mut out = Vec::new();
        let mut input = fed.as_slice();
        while !input.is_empty() {
            out.reserve(1 << 16);
            let before = (self.0.total_in(), self.0.total_out());
            let status = self
                .0
                .decompress_vec(input, &mut out, FlushDecompress::None)
                .map_err(|error| error.to_string())?;
            let consumed = usize::try_from(self.0.total_in() - before.0).expect("fits");
            let produced = self.0.total_out() - before.1;
            input = &input[consumed..];
            if status == Status::StreamEnd {
                return Err(format!("ended with {} octets unread", input.len()));
            }
            // Unpinned defence in depth. On every message tried this fires one
            // round after the check above rather than instead of it, and no
            // constructed input reaches it first -- so no row can go red on it
            // alone, and a row that cannot fail would only launder that. Kept
            // because a stall with input still to read is wrong whatever caused
            // it: green here means unpinned, not unnecessary.
            if consumed == 0 && produced == 0 {
                return Err(format!("no progress with {} octets left", input.len()));
            }
        }
        Ok(out)
    }
}

/// `Verifier::accept` without those two refusals: it returns the plaintext and
/// stops at the first round that makes no progress.
///
/// Kept for one row, which needs to show what an oracle that reads this way
/// accepts. Nothing else may use it.
fn without_the_tail_checks(wire: &[u8]) -> Result<Vec<u8>, String> {
    let mut inflater = Decompress::new_with_window_bits(false, 15);
    let mut fed = wire.to_vec();
    fed.extend_from_slice(TRAILER);
    let mut out = Vec::new();
    let mut input = fed.as_slice();
    while !input.is_empty() {
        out.reserve(1 << 16);
        let before = (inflater.total_in(), inflater.total_out());
        inflater
            .decompress_vec(input, &mut out, FlushDecompress::None)
            .map_err(|error| error.to_string())?;
        let consumed = usize::try_from(inflater.total_in() - before.0).expect("fits");
        let produced = inflater.total_out() - before.1;
        input = &input[consumed..];
        if consumed == 0 && produced == 0 {
            break;
        }
    }
    Ok(out)
}

/// RFC 7692 section 7.2.1 run by hand on `flate2`, for the rows that compare the
/// encoder's bytes with what the backend would produce at a given level.
///
/// Same arm, same build, by construction: `gate-no-cross-arm-byte-diff` forbids
/// comparing one backend's bytes with another's, and this never leaves the arm
/// it was compiled into.
///
/// Buffered at 1 MiB, deliberately *not* the crate's own per-round room. Matching
/// a reference that shares the encoder's buffer strategy would prove only that the
/// two agree; matching one buffered differently is what makes the comparison
/// evidence at all.
///
/// It does not show the encoder's output is buffer-independent, and must not be
/// read that way: level 0 above the payload-derived branch is not, which is why
/// the row that uses this helper scopes its byte assertions.
fn direct(level: u32, window_bits: u8, payload: &[u8]) -> Vec<u8> {
    let mut compressor =
        Compress::new_with_window_bits(Compression::new(level), false, window_bits);
    {
        {
            let mut out = Vec::new();
            let mut input = payload;
            while !input.is_empty() {
                out.reserve(1 << 20);
                let before = (compressor.total_in(), compressor.total_out());
                compressor
                    .compress_vec(input, &mut out, FlushCompress::None)
                    .expect("the backend compresses");
                let consumed = usize::try_from(compressor.total_in() - before.0).expect("fits");
                if consumed == 0 && compressor.total_out() == before.1 {
                    break;
                }
                input = &input[consumed..];
            }
            loop {
                out.reserve(1 << 20);
                let before = compressor.total_out();
                compressor.compress_vec(&[], &mut out, FlushCompress::Sync).expect("it flushes");
                if compressor.total_out() == before {
                    break;
                }
            }
            if out.ends_with(TRAILER) {
                out.truncate(out.len() - TRAILER.len());
                out
            } else {
                assert!(payload.is_empty(), "only an empty payload may yield no trailer");
                EMPTY_MESSAGE.to_vec()
            }
        }
    }
}

// -------------------------------------------------------------- the fixtures

/// Bytes with no internal redundancy, so a message that carries them twice can
/// only shrink by referring back to the earlier copy.
///
/// That is what makes a fixture *history-dependent* rather than merely
/// compressible, and history dependence is the only thing that gives the
/// takeover and synchronization rows the power to detect anything.
fn incompressible(len: usize, seed: u32) -> Vec<u8> {
    (0..u32::try_from(len).expect("fits"))
        .map(|i| ((i.wrapping_add(seed).wrapping_mul(2_654_435_761)) >> 24) as u8)
        .collect()
}

/// A payload whose compressed bytes differ across levels, so a level that was
/// ignored or remapped changes the output.
fn level_discriminating() -> Vec<u8> {
    let mut corpus = Vec::new();
    corpus.extend_from_slice(&incompressible(4_000, 11));
    for _ in 0..64 {
        corpus.extend_from_slice(b"permessage-deflate; client_max_window_bits=15; ");
    }
    corpus.extend_from_slice(&vec![b'z'; 3_000]);
    corpus.extend_from_slice(&incompressible(4_000, 11));
    corpus
}

// ------------------------------------------------------------- the agreements

/// A client pair at an exact negotiated width and takeover setting, built by
/// running the real handshake rather than by constructing an agreement beside it.
fn client_codecs(local: u8, peer: u8, takeover: bool, config: EncoderConfig) -> Encoder {
    client_pair(local, peer, takeover, config).0
}

/// The same agreement kept whole, for the rows that need the decoder too.
fn client_pair(local: u8, peer: u8, takeover: bool, config: EncoderConfig) -> (Encoder, Decoder) {
    let client = ClientConfig::new()
        .client_no_context_takeover(takeover)
        .client_max_window_bits(local)
        .expect("a local width in 9..=15")
        .server_max_window_bits(peer)
        .expect("a peer width in 8..=15");
    let mut request = HeaderMap::new();
    let offer = ClientOffer::install(client, &mut request).expect("fresh map");
    let response = format!(
        "permessage-deflate{}; server_max_window_bits={peer}; client_max_window_bits={local}",
        if takeover { "; client_no_context_takeover" } else { "" }
    );
    let mut headers = HeaderMap::new();
    headers.append(
        SEC_WEBSOCKET_EXTENSIONS,
        HeaderValue::from_str(&response).expect("a valid header value"),
    );
    offer
        .seal(&request)
        .expect("the offer is unchanged")
        .finish(&headers, PmdComposition::Compatible)
        .expect("the response is legal")
        .expect("the server selected it")
        .into_codecs(config)
}

/// A server pair at an exact negotiated width and takeover setting.
fn server_codecs(local: u8, peer: u8, takeover: bool, config: EncoderConfig) -> Encoder {
    let server = ServerConfig::new()
        .server_no_context_takeover(takeover)
        .server_max_window_bits(local)
        .expect("a local width in 9..=15")
        .client_max_window_bits(peer)
        .expect("a peer width in 8..=15");
    let mut request = HeaderMap::new();
    request.append(
        SEC_WEBSOCKET_EXTENSIONS,
        HeaderValue::from_static("permessage-deflate; client_max_window_bits"),
    );
    let handshake =
        ServerHandshake::accept(server, &request).expect("the request is legal").expect("selected");
    let mut response = HeaderMap::new();
    response.append(SEC_WEBSOCKET_EXTENSIONS, handshake.value().clone());
    handshake
        .finish(&response, PmdComposition::Compatible)
        .expect("the response is the crate's own element")
        .expect("the server selected it")
        .into_codecs(config)
        .0
}

/// The ordinary client encoder: widest window, history retained.
fn takeover_encoder() -> Encoder {
    client_codecs(15, 15, false, EncoderConfig::new())
}

/// Prepare and commit one message.
fn send(encoder: &mut Encoder, payload: &[u8]) -> Vec<u8> {
    encoder.prepare_message(payload).expect("a prepared message").commit()
}

/// Stream one message and return its fragment payloads in order.
///
/// The last chunk is always the final fragment, so a one-element slice is a
/// single-fragment message rather than an unterminated stream.
fn stream(encoder: &mut Encoder, chunks: &[&[u8]]) -> Vec<Vec<u8>> {
    let (last, leading) = chunks.split_last().expect("a message ends with a final fragment");
    let mut open = encoder.begin_streaming_message().expect("a stream");
    let mut fragments = Vec::new();
    for chunk in leading {
        let (bytes, next) = open.prepare_non_final_fragment(chunk).expect("a fragment").commit();
        fragments.push(bytes);
        open = next;
    }
    fragments.push(last_fragment(open, last));
    fragments
}

/// The final fragment alone, so a row can end a stream it built by hand.
fn last_fragment(open: StreamingMessage<'_>, payload: &[u8]) -> Vec<u8> {
    open.prepare_final_fragment(payload).expect("a final fragment").commit()
}

/// RFC 7692 section 7.2.1 steps 1 and 2 run by hand on `flate2`, once per chunk.
///
/// Same arm and buffered at 1 MiB, for the reason [`direct`] gives. What it does
/// *not* do is step 3: every chunk comes back with whatever trailer the flush
/// produced, the final one included. The row that pins the strip deletes those
/// four octets itself after asserting they are there, so the expectation is never
/// produced by the same tail search the production code performs.
fn direct_stream_aligned(level: u32, window_bits: u8, chunks: &[&[u8]]) -> Vec<Vec<u8>> {
    let mut compressor =
        Compress::new_with_window_bits(Compression::new(level), false, window_bits);
    chunks
        .iter()
        .map(|chunk| {
            let mut out = Vec::new();
            let mut input = *chunk;
            while !input.is_empty() {
                out.reserve(1 << 20);
                let before = (compressor.total_in(), compressor.total_out());
                compressor
                    .compress_vec(input, &mut out, FlushCompress::None)
                    .expect("the backend compresses");
                let consumed = usize::try_from(compressor.total_in() - before.0).expect("fits");
                if consumed == 0 && compressor.total_out() == before.1 {
                    break;
                }
                input = &input[consumed..];
            }
            loop {
                out.reserve(1 << 20);
                let before = compressor.total_out();
                compressor.compress_vec(&[], &mut out, FlushCompress::Sync).expect("it flushes");
                if compressor.total_out() == before {
                    break;
                }
            }
            out
        })
        .collect()
}

/// A whole streamed message as the peer's inflater receives it: the fragments in
/// order, with the one stripped trailer fed back by [`Verifier::accept`].
fn on_the_wire(fragments: &[Vec<u8>]) -> Vec<u8> {
    fragments.concat()
}

// ------------------------------------------------------- gate-rfc-vectors

/// RFC 7692's own worked examples, byte for byte, at the backend's default
/// level.
///
/// These four rows are the transform's flate2-independent oracle: they were
/// published with the specification and cover the deflate step, the strip,
/// context takeover, the no-context reset, and the empty message. A failure here
/// is a finding to investigate, not a test to relax.
///
/// Asserted at the default level only. Outside the RFC-pinned configuration two
/// conforming backends may choose different bytes for the same message — level 1
/// is a measured example — so other levels are exercised by `the_encoder_matches
/// _direct_flate2_at_every_level` against the same arm instead.
#[test]
fn the_rfc_7692_vectors_are_reproduced_byte_for_byte() {
    let mut encoder = takeover_encoder();
    assert_eq!(
        send(&mut encoder, b"Hello"),
        [0xf2, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x00],
        "section 7.2.3.1, first message"
    );
    assert_eq!(
        send(&mut encoder, b"Hello"),
        [0xf2, 0x00, 0x11, 0x00, 0x00],
        "section 7.2.3.2, second message with context takeover"
    );

    // Section 7.2.3.4: after a no-context reset the first vector returns.
    let mut reset = client_codecs(15, 15, true, EncoderConfig::new());
    assert_eq!(send(&mut reset, b"Hello"), [0xf2, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x00]);
    assert_eq!(
        send(&mut reset, b"Hello"),
        [0xf2, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x00],
        "the reset must return the second message to the first vector"
    );

    // Section 7.2.3.6, and section 7.2.3.3's level-0 frame minus its two header
    // octets. The RFC's prose there says "Payload length=7" while its own length
    // octet is 0x0b and its "3rd to 13th octets" both say 11; the octets are
    // asserted, that sentence is not.
    assert_eq!(send(&mut takeover_encoder(), b""), EMPTY_MESSAGE, "section 7.2.3.6");
    let mut stored =
        client_codecs(15, 15, false, EncoderConfig::new().compression_level(0).expect("level 0"));
    assert_eq!(
        send(&mut stored, b"Hello"),
        [0x00, 0x05, 0x00, 0xfa, 0xff, 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x00],
        "section 7.2.3.3, the level-0 stored route"
    );
}

// ----------------------------------------------------- gate-rfc-transform

/// The whole payload reaches the wire, the trailer is removed exactly, and a
/// message far larger than one backend round still round-trips.
#[test]
fn a_message_spanning_many_backend_rounds_round_trips_exactly() {
    let mut encoder = takeover_encoder();
    let mut verifier = Verifier::new();
    for len in [0usize, 1, 5, 4_095, 4_096, 4_097, 200_000] {
        let payload = incompressible(len, 7);
        let wire = send(&mut encoder, &payload);
        assert!(
            !wire.ends_with(TRAILER),
            "len {len}: the four-octet trailer must be removed, not left on"
        );
        assert_eq!(verifier.accept(&wire).expect("valid stream"), payload, "len {len}");
    }
}

/// The empty message reaches `0x00` by two different routes, and they are two
/// rows because they exercise different code.
///
/// A fresh compressor emits the five-octet empty block, so the first row runs
/// the backend and the ordinary strip. An empty message that directly follows
/// another under takeover yields nothing at all — both locked backends refuse a
/// redundant flush — so the second row runs the section 7.2.3.6 synthesis.
///
/// Keeping the first row on the backend path is what preserves it as the
/// discriminator for an over- or under-stripped trailer. A universal constant
/// would have satisfied it with the strip deleted.
#[test]
fn an_empty_message_reaches_the_rfc_octet_by_both_routes() {
    // Route one: the backend produces it, the strip removes four.
    assert_eq!(send(&mut takeover_encoder(), b""), EMPTY_MESSAGE, "fresh compressor");
    let mut after_reset = client_codecs(15, 15, true, EncoderConfig::new());
    assert_eq!(send(&mut after_reset, b"Hello"), [0xf2, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x00]);
    assert_eq!(send(&mut after_reset, b""), EMPTY_MESSAGE, "after a no-context reset");

    // Route two: the backend produces nothing and the synthesis supplies it.
    let mut encoder = takeover_encoder();
    let _ = send(&mut encoder, b"Hello");
    assert_eq!(send(&mut encoder, b""), EMPTY_MESSAGE, "immediate second empty under takeover");
    assert_eq!(send(&mut encoder, b""), EMPTY_MESSAGE, "and again, with nothing in between");
}

// ------------------------------------------- gate-empty-synchronization

/// A synthesized empty message leaves this side's compressor and the peer's
/// inflater in step.
///
/// The row is non-empty commit, synthesized empty, then a message that depends
/// on the first one's history, all through one inflater. Two preconditions run
/// *before* the result counts, because without them the row cannot fail: if the
/// third payload happened to carry no back-reference, an inflater would
/// reconstruct it correctly whatever its window held, and a desync introduced by
/// the empty message would leave all three payloads exact.
#[test]
fn a_synthesized_empty_message_preserves_stream_state() {
    let payload = incompressible(4_000, 23);
    let mut encoder = takeover_encoder();
    let first = send(&mut encoder, &payload);
    let empty = send(&mut encoder, b"");
    assert_eq!(empty, EMPTY_MESSAGE, "the middle message must be the synthesized octet");
    let third = send(&mut encoder, &payload);

    // control-same-arm-candidate: the same payload on a fresh compressor in this
    // arm. If the two agree the fixture has no history dependence at all, and
    // that is a fixture error rather than a passing row.
    let fresh_candidate = send(&mut takeover_encoder(), &payload);
    assert_ne!(
        third,
        fresh_candidate,
        "the third message does not depend on the first's history: {} bytes either way, so this \
         row cannot detect a desync",
        third.len()
    );

    // control-fresh-inflater: an inflater without the history must fail or
    // differ on that third message.
    let solo = Verifier::new().accept(&third);
    assert!(
        solo.as_deref() != Ok(payload.as_slice()),
        "a fresh inflater recovered the third message, so it carries no back-reference"
    );

    // Only now does exact recovery through the shared inflater prove anything.
    let mut shared = Verifier::new();
    assert_eq!(shared.accept(&first).expect("first"), payload, "message 1");
    assert_eq!(shared.accept(&empty).expect("empty"), Vec::<u8>::new(), "message 2 is empty");
    assert_eq!(shared.accept(&third).expect("third"), payload, "message 3 after the empty");
}

// ------------------------------------------------------------ gate-takeover

/// Retained history is real, and dropping it is real.
#[test]
fn takeover_retains_history_and_no_context_drops_it() {
    let payload = incompressible(4_000, 41);

    let mut retaining = takeover_encoder();
    let first = send(&mut retaining, &payload);
    let second = send(&mut retaining, &payload);
    let mut shared = Verifier::new();
    assert_eq!(shared.accept(&first).expect("first"), payload);
    assert_eq!(shared.accept(&second).expect("second"), payload);
    assert!(
        Verifier::new().accept(&second).as_deref() != Ok(payload.as_slice()),
        "a fresh inflater must not recover a message that referred to retained history"
    );

    let mut dropping = client_codecs(15, 15, true, EncoderConfig::new());
    for round in 0..3 {
        let wire = send(&mut dropping, &payload);
        assert_eq!(
            Verifier::new().accept(&wire).expect("valid stream"),
            payload,
            "round {round}: under no-context each message must stand alone"
        );
    }
}

// --------------------------------------------------------- gate-transaction

/// Committing returns the advanced history; resetting to plain discards it.
#[test]
fn reset_to_plain_discards_the_candidate_and_its_history() {
    let payload = incompressible(4_000, 59);
    for takeover in [false, true] {
        let mut encoder = client_codecs(15, 15, takeover, EncoderConfig::new());
        let first = send(&mut encoder, &payload);
        assert_eq!(Verifier::new().accept(&first).expect("valid stream"), payload);

        // A candidate that is prepared and then abandoned.
        encoder.prepare_message(&payload).expect("prepared").reset_to_plain();

        // A verifier that never saw the discarded candidate must still recover
        // the next committed message. That is only possible if the encoder
        // stopped referring to the history that candidate advanced --
        // `takeover_retains_history_and_no_context_drops_it` is the control
        // showing this same payload does *not* decode standalone when history
        // was kept.
        let next = send(&mut encoder, &payload);
        assert_eq!(
            Verifier::new().accept(&next).expect("valid stream"),
            payload,
            "takeover {takeover}"
        );
    }
}

/// A peer that kept its own history still decodes the message after a
/// `reset_to_plain`.
///
/// This is the wire half of the argument `PreparedMessage::reset_to_plain`
/// makes. Every other reset-to-plain row checks it with a fresh inflater, which
/// proves the next message is self-contained but never puts a history-holding
/// peer on the far end -- the position every real connection is in, because the
/// abandoned candidate is precisely the message the peer never received.
///
/// The presence control runs first. If the payload did not compress against
/// retained history, an encoder that never reset would emit the same bytes as
/// one that did, and the row could not fail.
#[test]
fn a_history_keeping_peer_decodes_the_message_after_a_reset_to_plain() {
    let sent = incompressible(4_000, 71);
    let abandoned = incompressible(4_000, 73);

    let mut control = takeover_encoder();
    let standalone = send(&mut control, &abandoned).len();
    let against_history = send(&mut control, &abandoned).len();
    assert!(
        against_history * 4 < standalone,
        "the fixture must compress against retained history: {against_history} vs {standalone}"
    );

    let mut encoder = takeover_encoder();
    let mut peer = Verifier::new();
    let first = send(&mut encoder, &sent);
    assert_eq!(peer.accept(&first).expect("first"), sent);

    // The peer never sees these bytes, so its window does not move -- and an
    // encoder that kept them would compress the next message against them.
    encoder.prepare_message(&abandoned).expect("prepared").reset_to_plain();

    let next = send(&mut encoder, &abandoned);
    assert_eq!(peer.accept(&next).expect("valid stream"), abandoned);
}

/// An unresolved candidate poisons the direction, however it went unresolved.
#[test]
fn an_unresolved_candidate_poisons_the_encoder() {
    // Dropped.
    let mut dropped = takeover_encoder();
    drop(dropped.prepare_message(b"Hello").expect("prepared"));
    assert_eq!(
        dropped.prepare_message(b"Hello").expect_err("poisoned"),
        CodecError::Poisoned,
        "after drop"
    );
    assert_eq!(
        dropped.prepare_message(b"").expect_err("poisoned"),
        CodecError::Poisoned,
        "and again"
    );

    // Leaked. Safe `mem::forget` never runs `Drop`, which is exactly why the
    // compressor lives inside the guard rather than being restored by one.
    let mut forgotten = takeover_encoder();
    core::mem::forget(forgotten.prepare_message(b"Hello").expect("prepared"));
    assert_eq!(
        forgotten.prepare_message(b"Hello").expect_err("poisoned"),
        CodecError::Poisoned,
        "after mem::forget"
    );

    // A committed message leaves the encoder usable; only an unresolved one does
    // not. Without this the row would pass on an encoder that poisons always.
    let mut healthy = takeover_encoder();
    let _ = send(&mut healthy, b"Hello");
    assert!(healthy.prepare_message(b"Hello").is_ok(), "a resolved candidate must not poison");
}

/// The candidate is writable for a reversible transport transform, and the
/// transform does not change what the peer inflates.
#[test]
fn a_masked_candidate_still_decodes_after_unmasking() {
    let payload = incompressible(4_000, 71);
    let mut encoder = takeover_encoder();
    let mut prepared = encoder.prepare_message(&payload).expect("prepared");
    let mask = [0x37u8, 0xfa, 0x21, 0x3d];
    for (i, byte) in prepared.as_bytes_mut().iter_mut().enumerate() {
        *byte ^= mask[i % 4];
    }
    let mut wire = prepared.commit();
    for (i, byte) in wire.iter_mut().enumerate() {
        *byte ^= mask[i % 4];
    }
    assert_eq!(Verifier::new().accept(&wire).expect("valid stream"), payload);
}

// -------------------------------------------------------------- gate-level

/// Every accepted level routes to the backend at that exact level, and the
/// comparison is inside one arm and one build.
///
/// The corpus is asserted to discriminate before the comparison is trusted: if
/// every level produced the same bytes, matching direct flate2 at "that level"
/// would say nothing about which level was used.
#[test]
fn the_encoder_matches_direct_flate2_at_every_level() {
    let corpus = level_discriminating();
    let mut outputs = Vec::new();
    for level in 0..=9u32 {
        let config = EncoderConfig::new().compression_level(level).expect("zlib's domain");
        let mut encoder = client_codecs(15, 15, false, config);
        let ours = send(&mut encoder, &corpus);
        assert_eq!(ours, direct(level, 15, &corpus), "level {level}");
        assert_eq!(Verifier::new().accept(&ours).expect("valid stream"), corpus, "level {level}");
        outputs.push(ours);
    }

    let mut distinct = outputs.clone();
    distinct.sort_unstable();
    distinct.dedup();
    assert!(
        distinct.len() >= 3,
        "the corpus separates only {} of the ten levels, so a remap could survive",
        distinct.len()
    );
    assert!(
        outputs[9].len() < outputs[0].len(),
        "level 9 must produce a materially smaller stream than level 0: {} against {}",
        outputs[9].len(),
        outputs[0].len()
    );
}

/// The level survives both reset routes, which is what makes the encoder's
/// missing rebuild branch correct rather than lucky.
#[test]
fn the_level_survives_both_reset_resolutions() {
    let corpus = level_discriminating();
    for level in 0..=9u32 {
        let config = EncoderConfig::new().compression_level(level).expect("zlib's domain");
        let expected = &direct(level, 15, &corpus);

        // After a no-context commit reset.
        let mut committing = client_codecs(15, 15, true, config);
        let _ = send(&mut committing, &corpus);
        assert_eq!(&send(&mut committing, &corpus), expected, "level {level} after commit reset");

        // After reset-to-plain.
        let mut abandoning = client_codecs(15, 15, false, config);
        abandoning.prepare_message(&corpus).expect("prepared").reset_to_plain();
        assert_eq!(&send(&mut abandoning, &corpus), expected, "level {level} after reset-to-plain");
    }
}

// -------------------------------------------------------- gate-window-route

/// Every local width both roles can negotiate builds a working compressor, at
/// fresh construction and after both reset resolutions.
#[test]
fn every_local_width_round_trips_for_both_roles() {
    let payload = incompressible(40_000, 83);
    for local in 9..=15u8 {
        // Differs from the local width at every row, so a swapped read shows.
        let peer = if local == 15 { 9 } else { 15 };
        for role in ["client", "server"] {
            let build = |takeover: bool| {
                if role == "client" {
                    client_codecs(local, peer, takeover, EncoderConfig::new())
                } else {
                    server_codecs(local, peer, takeover, EncoderConfig::new())
                }
            };

            let mut fresh = build(false);
            let wire = send(&mut fresh, &payload);
            assert_eq!(
                Verifier::new().accept(&wire).expect("valid stream"),
                payload,
                "{role}, local {local}, fresh"
            );

            let mut committing = build(true);
            let _ = send(&mut committing, &payload);
            let wire = send(&mut committing, &payload);
            assert_eq!(
                Verifier::new().accept(&wire).expect("valid stream"),
                payload,
                "{role}, local {local}, after a no-context commit reset"
            );

            let mut abandoning = build(false);
            abandoning.prepare_message(&payload).expect("prepared").reset_to_plain();
            let wire = send(&mut abandoning, &payload);
            assert_eq!(
                Verifier::new().accept(&wire).expect("valid stream"),
                payload,
                "{role}, local {local}, after reset-to-plain"
            );
        }
    }
}

/// A narrow local window bounds how far back the compressor may refer, and it is
/// observable in the output size on both backends.
///
/// This is what guards a hardcoded or swapped width inside the encoder's
/// builder, which the mapping unit test cannot: `Compress` exposes no read-back.
/// The presence control runs first — the payload must actually carry a reference
/// that a 15-bit window reaches and a 9-bit one does not — so the row measures a
/// window rather than a mood.
#[test]
fn the_local_window_bounds_back_references() {
    let block = incompressible(12_000, 97);
    let filler = incompressible(12_000, 131);
    let mut payload = block.clone();
    payload.extend_from_slice(&filler);
    payload.extend_from_slice(&block);

    let widest = send(&mut client_codecs(15, 15, false, EncoderConfig::new()), &payload);
    let narrowest = send(&mut client_codecs(9, 15, false, EncoderConfig::new()), &payload);
    assert!(
        widest.len() < narrowest.len(),
        "the fixture carries no far reference for a window to bound: 15 gave {} and 9 gave {}",
        widest.len(),
        narrowest.len()
    );
    assert_eq!(Verifier::new().accept(&widest).expect("valid at 15"), payload);
    assert_eq!(Verifier::new().accept(&narrowest).expect("valid at 9"), payload);
}

// ------------------------------------------------------ gate-fragment-split

/// A host may split a `prepare_message` payload anywhere; on that path the
/// encoder never sees a fragment.
///
/// RFC 7692 section 7.2.1: "An endpoint fragments a compressed message by
/// splitting the result of running this algorithm." That is the strategy
/// `prepare_message` implements, and this row stays inside it: the trailer is
/// removed once, from the complete result, and the host cuts the bytes wherever
/// it likes.
///
/// The adjacent MUST NOT — that `00 00 ff ff` is not removed from non-final
/// fragments — governs the *other* strategy, one encoder call per fragment.
/// `begin_streaming_message` is that strategy and nothing here enters it; the
/// rows that do are `gate-nonfinal-tail` and `gate-composite-peer`. The contrast
/// is the point of this row, so scoping it is not the same as retiring it.
#[test]
fn host_side_fragment_splitting_preserves_the_bytes() {
    let payload = incompressible(50_000, 149);
    let mut encoder = takeover_encoder();
    let wire = send(&mut encoder, &payload);

    for pieces in [2usize, 3, 7, 64] {
        let mut verifier = Verifier::new();
        // The trailer belongs at the end of the message, not of each fragment,
        // so the fragments are fed as one stream with the trailer appended once.
        let mut fed = wire.clone();
        fed.extend_from_slice(TRAILER);
        let step = fed.len() / pieces + 1;
        let mut out = Vec::new();
        let mut cursor = 0;
        while cursor < fed.len() {
            let end = (cursor + step).min(fed.len());
            out.reserve(1 << 16);
            verifier
                .0
                .decompress_vec(&fed[cursor..end], &mut out, FlushDecompress::None)
                .expect("valid stream");
            cursor = end;
        }
        assert_eq!(out, payload, "{pieces} fragments");
    }
}

/// The encoder emits no redundant empty blocks.
///
/// The reference is buffered at 1 MiB, deliberately *not* the crate's own
/// per-round room: matching a compressor that shares the encoder's buffer
/// strategy would prove only that the two agree.
///
/// A repeated sync flush that was already complete appends a second empty stored
/// block — valid wire, five wasted octets, invisible to every round-trip row in
/// this file, and detectable only by comparing against a differently buffered
/// compressor. Before the encoder gave the flush room to finish in one call, most
/// large level-0 messages carried one.
///
/// Level 0 splits into two bands, and the split is the encoder's own room branch
/// rather than a convenience. Below the ceiling the room is derived from the
/// payload, and level 0 is byte-exact there — that band is the *only* place the
/// encoder's framing margin is observable, because a flush that outgrows its room
/// by even one octet appends a redundant block. `FRAMING_MARGIN`'s own doc has
/// the number: consumption is `5 x blocks + 5`, and at most two blocks fit below
/// the branch edge, so it is ten or fifteen octets, and the worst case leaves 49
/// of the 64 unused -- bounded by arithmetic, not by the sizes sampled here.
///
/// Above the ceiling the room is a constant, and zlib sizes each stored block from
/// what it is handed, so a message whose output needs more than one round emits
/// one more block header than an unbounded compressor would. No fixed room stops
/// that — the first affected size tracks the room itself, measured at three
/// ceilings — and removing it would mean reserving every message in full, taxing
/// the compressible common case to tidy the incompressible one. Those sizes are
/// validity-only, with level 0's bytes pinned instead by RFC 7692 section 7.2.3.3
/// in `the_rfc_7692_vectors_are_reproduced_byte_for_byte` and by the same-arm
/// routing comparison in `the_encoder_matches_direct_flate2_at_every_level`.
///
/// Levels 1 through 9 are byte-identical at every size here, including the
/// stored-block multiples and the sizes either side of the room ceiling, which is
/// where the level-0 divergence lives.
#[test]
fn the_encoder_matches_a_differently_buffered_compressor() {
    // The encoder derives its room from the payload below this and uses a
    // constant above it. Naming the branch boundary is not the same as restating
    // the arithmetic behind it: below it, level 0 is byte-exact and is what holds
    // the framing margin.
    const PAYLOAD_ROOM_BAND: usize = 131_008;

    // Three bands. The maximal-stored-block multiples and the sizes either side of
    // the crate's per-round room ceiling, where the level-0 divergence lives; and
    // zlib's 16,384-symbol literal buffer with its multiples, which is where the
    // payload-derived room branch would show a residue larger than its margin.
    let sizes = [
        1usize, 5, 4_096, 16_384, 16_448, 32_768, 60_000, 65_534, 65_535, 65_536, 98_304, 131_006,
        131_007, 131_070, 131_071, 131_072, 131_073, 196_605, 200_000, 400_000,
    ];
    for level in 0..=9u32 {
        for len in sizes {
            for (shape, payload) in
                [("incompressible", incompressible(len, 199)), ("repetitive", vec![b'q'; len])]
            {
                let config = EncoderConfig::new().compression_level(level).expect("zlib's domain");
                let ours = send(&mut client_codecs(15, 15, false, config), &payload);
                let reference = direct(level, 15, &payload);
                if level > 0 || len <= PAYLOAD_ROOM_BAND {
                    assert_eq!(
                        ours.len(),
                        reference.len(),
                        "level {level}, {shape}, {len} bytes: the encoder emitted {} octets where \
                         a 1-MiB-buffered compressor emits {}",
                        ours.len(),
                        reference.len()
                    );
                    assert_eq!(ours, reference, "level {level}, {shape}, {len} bytes");
                }
                assert_eq!(
                    Verifier::new().accept(&ours).expect("valid stream"),
                    payload,
                    "level {level}, {shape}, {len} bytes"
                );
            }
        }
    }
}

// --------------------------------------------------------- gate-public-shape

/// The whole streaming sequence through public imports: begin, non-final
/// prepare, inspect, mask and unmask, commit, final prepare, commit.
///
/// A shape and ownership row. Recovering the plaintext here proves the states
/// hand the compressor along correctly and that a host can drive them; it is not
/// conformance evidence, which is `gate-composite-peer`'s job against a peer that
/// is not this crate.
#[test]
fn a_host_drives_the_whole_streaming_sequence() {
    let mut encoder = takeover_encoder();
    let chunks: [&[u8]; 3] =
        [b"a message that arrives ", b"in three pieces, ", b"masked in flight"];

    let mut open = encoder.begin_streaming_message().expect("a stream");
    let mut wire = Vec::new();
    for chunk in &chunks[..2] {
        let mut fragment = open.prepare_non_final_fragment(chunk).expect("a fragment");
        assert!(!fragment.as_bytes().is_empty(), "a non-empty chunk produces bytes");

        // The reversible transport transform a client applies, and undoes here
        // so the peer sees what the encoder produced.
        let mask = [0x37u8, 0xfa, 0x21, 0x3d];
        for (i, byte) in fragment.as_bytes_mut().iter_mut().enumerate() {
            *byte ^= mask[i % 4];
        }
        let (mut bytes, next) = fragment.commit();
        for (i, byte) in bytes.iter_mut().enumerate() {
            *byte ^= mask[i % 4];
        }
        wire.push(bytes);
        open = next;
    }

    let mut last = open.prepare_final_fragment(chunks[2]).expect("a final fragment");
    assert!(!last.as_bytes_mut().is_empty(), "mutable access reaches the final candidate too");
    wire.push(last.commit());

    // One peer for the whole connection, because the encoder retains history
    // across the message boundary and the follow-up may reference back into the
    // streamed message. A fresh inflater for the second message is a real bug
    // that only one backend reports: zlib-rs happened to choose matches that did
    // not reach back, and C zlib refused the same row with "invalid distance too
    // far back".
    let mut peer = Verifier::new();
    assert_eq!(
        peer.accept(&on_the_wire(&wire)).expect("a valid stream"),
        chunks.concat(),
        "the three chunks, in order, exactly"
    );

    // And the encoder is back: a streamed message is not a terminal state.
    assert_eq!(
        peer.accept(&send(&mut encoder, b"after the stream")).expect("valid"),
        b"after the stream"
    );
}

// ------------------------------------------------------------ gate-peer-oracle

/// The oracle every other row is measured through, against a message it must
/// refuse.
///
/// Setting BFINAL on the first block leaves the DEFLATE stream decodable and
/// ends it early: the plaintext still comes out, and the four octets this
/// verifier appended are never read. An inflater that reports only the
/// plaintext therefore calls a wire correct while agreeing with a producer it
/// stopped reading, and every payload assertion in this file inherits that.
///
/// Measured, not assumed: on this message `Verifier` consumes 11 of 11 octets
/// and never reports `StreamEnd`; with the bit set it consumes 7 and does.
///
/// The refusal is pinned to the `StreamEnd` arm by its message. The
/// zero-progress arm catches this same input one round later and is kept as a
/// second detector, but no input here separates the two -- so this row shows
/// that at least one refusal fires, and which one, rather than exercising both.
#[test]
fn an_early_final_block_is_read_as_a_message_that_ended_unread() {
    let mut encoder = takeover_encoder();
    let wire = send(&mut encoder, b"Hello");

    let mut early = wire.clone();
    early[0] |= 0b0000_0001;

    assert_eq!(
        without_the_tail_checks(&early).as_deref(),
        Ok(&b"Hello"[..]),
        "an oracle that stops at the plaintext calls this message correct",
    );

    let refused = Verifier::new().accept(&early).expect_err("the trailer went unread");
    assert!(
        refused.contains("ended with 4 octets unread"),
        "refused, but not as a premature end: {refused}",
    );

    assert_eq!(
        Verifier::new().accept(&wire).expect("valid stream"),
        b"Hello",
        "and the message the encoder actually produced still passes",
    );
}

// -------------------------------------------------------- gate-composite-peer

/// A streamed message decodes to exactly its chunks, through an inflater built
/// directly on `flate2`.
///
/// The conformance row for continuity and for the non-final trailer rule, and
/// the three negative controls are what say so: strip a non-final fragment's
/// trailer, drop a middle fragment, or flip one octet, and the peer must fail or
/// return something else. What this oracle *cannot* see was measured too —
/// removing or duplicating the final empty block leaves it green — so the final
/// strip is pinned by bytes in `gate-final-strip-bytes` and not here.
#[test]
fn a_streamed_message_decodes_through_a_direct_peer() {
    let long = incompressible(40_000, 23);
    let sequences: [Vec<&[u8]>; 5] = [
        vec![b"one fragment only"],
        vec![b"first ", b"second ", b"third"],
        vec![b"a message that ends empty", b""],
        vec![b"", b"a message that starts empty"],
        vec![&long[..17_000], &long[17_000..33_000], &long[33_000..]],
    ];

    for chunks in &sequences {
        let mut encoder = takeover_encoder();
        let fragments = stream(&mut encoder, chunks);
        let expected: Vec<u8> = chunks.concat();
        assert_eq!(
            Verifier::new().accept(&on_the_wire(&fragments)).expect("a valid stream"),
            expected,
            "{} fragments",
            chunks.len()
        );

        if chunks.len() < 2 {
            continue;
        }

        // Control one: a non-final fragment stripped the way a complete message
        // is. RFC 7692 section 7.2.1's MUST NOT, observed.
        let stripped: Vec<Vec<u8>> = fragments
            .iter()
            .enumerate()
            .map(|(i, fragment)| {
                if i + 1 < fragments.len() && fragment.ends_with(TRAILER) {
                    fragment[..fragment.len() - TRAILER.len()].to_vec()
                } else {
                    fragment.clone()
                }
            })
            .collect();
        if stripped != fragments {
            assert_ne!(
                Verifier::new().accept(&on_the_wire(&stripped)).ok().as_ref(),
                Some(&expected),
                "stripping a non-final trailer must not still decode to the message"
            );
        }

        // Control two: an interior fragment dropped. Interior, and only when
        // there is one: this oracle is measurably blind to a missing *final*
        // empty block, so dropping index `len / 2` from a two-fragment sequence
        // would assert something known to be false rather than test anything.
        if fragments.len() >= 3 {
            let mut missing = fragments.clone();
            missing.remove(1);
            assert_ne!(
                Verifier::new().accept(&on_the_wire(&missing)).ok().as_ref(),
                Some(&expected),
                "a dropped interior fragment must not still decode to the message"
            );
        }

        // Control three: one octet flipped inside the largest fragment's data.
        // Interior on purpose. Octet zero is the DEFLATE block header, and its
        // low bit is BFINAL -- setting it ends the stream after a block that has
        // already produced the whole plaintext, so the peer returns the right
        // bytes and the control asserts nothing.
        let mut flipped = fragments.clone();
        if let Some(target) =
            flipped.iter_mut().max_by_key(|fragment| fragment.len()).filter(|f| f.len() >= 8)
        {
            let middle = target.len() / 2;
            target[middle] ^= 0x40;
            assert_ne!(
                Verifier::new().accept(&on_the_wire(&flipped)).ok().as_ref(),
                Some(&expected),
                "a flipped octet must not still decode to the message"
            );
        }
    }
}

// ----------------------------------------------------------- gate-nonfinal-tail

/// Every non-final fragment that produced bytes ends in `00 00 ff ff`, and an
/// empty chunk is the only one allowed to produce none.
///
/// The conditional is not caution. What an empty non-final chunk yields is
/// *positional* -- the five-octet empty block from a compressor that has not
/// just flushed, nothing at all from one that has -- so asserting a trailer
/// unconditionally would be red on a conforming backend.
#[test]
fn every_produced_non_final_fragment_keeps_its_trailer() {
    for level in [0u32, 1, 6, 9] {
        for sizes in [[1usize, 1, 1], [5, 4_096, 7], [40_000, 3, 65_540], [0, 8, 0]] {
            let config = EncoderConfig::new().compression_level(level).expect("zlib's domain");
            let mut encoder = client_codecs(15, 15, false, config);
            let payloads: Vec<Vec<u8>> = sizes.iter().map(|&len| incompressible(len, 61)).collect();
            let chunks: Vec<&[u8]> = payloads.iter().map(Vec::as_slice).collect();

            let mut open = encoder.begin_streaming_message().expect("a stream");
            let mut fragments = Vec::new();
            for (i, chunk) in chunks[..chunks.len() - 1].iter().enumerate() {
                let fragment = open.prepare_non_final_fragment(chunk).expect("a fragment");
                let bytes = fragment.as_bytes();
                if bytes.is_empty() {
                    assert!(
                        chunk.is_empty(),
                        "level {level}, fragment {i}: a chunk with bytes produced none"
                    );
                } else {
                    assert!(
                        bytes.ends_with(TRAILER),
                        "level {level}, fragment {i}: {} octets, tail {:02x?}",
                        bytes.len(),
                        &bytes[bytes.len().saturating_sub(8)..]
                    );
                }
                let (bytes, next) = fragment.commit();
                fragments.push(bytes);
                open = next;
            }
            fragments.push(last_fragment(open, chunks[chunks.len() - 1]));

            assert_eq!(
                Verifier::new().accept(&on_the_wire(&fragments)).expect("a valid stream"),
                chunks.concat(),
                "level {level}, sizes {sizes:?}"
            );
        }
    }
}

// ------------------------------------------------------- gate-final-strip-bytes

/// The final fragment removes exactly the last four octets.
///
/// The expectation is built here rather than taken from the crate: a same-arm
/// 1-MiB-buffered producer runs steps 1 and 2 over the identical chunk sequence,
/// this row asserts its raw output ends in the trailer, and then deletes exactly
/// four octets by index. A backward scan and an exact tail removal agree on
/// ordinary output, so the corpus is chosen where they cannot: level 0 stores the
/// payload verbatim, so a plaintext that *contains* `00 00 ff ff` — RFC 7692
/// section 7.2.3.5's shape — puts a second copy in the compressed bytes, and a
/// plaintext that *ends* with it puts one immediately before the flush's own.
///
/// The retained-tail counterfactual is the row's own control: the aligned output
/// with its trailer still on must differ from what the crate returns. Without it
/// an encoder that skipped step 3 entirely would pass every peer round trip in
/// this file: an inflater accepts the extra empty block, so no round trip in
/// either direction can stand in for this row.
///
/// What the row does *not* pin is how the four octets are found. Every case
/// asserts the reference output ends in the trailer before comparing, so a
/// backward search locates that terminal copy and agrees with an exact tail
/// removal everywhere here -- including the two rows whose plaintext carries a
/// copy of its own. Separating them needs a final fragment with an internal
/// trailer and none at the end, and a producer that sync-flushes cannot emit
/// one, so it is not a fixture this suite can build.
#[test]
fn the_final_fragment_strips_exactly_the_terminal_trailer() {
    let mut ends_with_trailer = b"stored plaintext ".to_vec();
    ends_with_trailer.extend_from_slice(TRAILER);
    let mut contains_trailer = b"before ".to_vec();
    contains_trailer.extend_from_slice(TRAILER);
    contains_trailer.extend_from_slice(b" after");

    let corpus: [(&str, Vec<&[u8]>); 4] = [
        ("plain single", vec![b"Hello"]),
        ("plain multi", vec![b"lead ", b"tail"]),
        ("final ends with the trailer", vec![b"lead ", &ends_with_trailer]),
        ("final contains the trailer", vec![b"lead ", &contains_trailer]),
    ];

    // Level 0 stores literally, which is what puts the plaintext's own copies of
    // the four octets into the compressed output; level 6 keeps an ordinary
    // case in the row so it is not a level-0-only claim.
    for level in [0u32, 6] {
        for (name, chunks) in &corpus {
            let config = EncoderConfig::new().compression_level(level).expect("zlib's domain");
            let ours = stream(&mut client_codecs(15, 15, false, config), chunks);
            let aligned = direct_stream_aligned(level, 15, chunks);
            let raw_final = aligned.last().expect("a final chunk");

            assert!(
                raw_final.ends_with(TRAILER),
                "level {level}, {name}: the reference produced no trailer to remove"
            );
            let expected = &raw_final[..raw_final.len() - TRAILER.len()];
            assert_eq!(
                ours.last().expect("a final fragment").as_slice(),
                expected,
                "level {level}, {name}: exactly four octets, deleted by index"
            );

            // The counterfactual this row exists to kill.
            assert_ne!(
                ours.last().expect("a final fragment").as_slice(),
                raw_final.as_slice(),
                "level {level}, {name}: the final fragment retained its trailer"
            );

            assert_eq!(
                Verifier::new().accept(&on_the_wire(&ours)).expect("a valid stream"),
                chunks.concat(),
                "level {level}, {name}"
            );
        }
    }
}

// ------------------------------------------------------------ gate-empty-final

/// An empty final chunk is RFC 7692 section 7.2.3.6's single `0x00`, by either
/// internal route.
///
/// The pair is the point. A fresh stream's empty final reaches the strip arm,
/// because the compressor has not flushed yet and produces the trailer; an empty
/// final after a committed non-final reaches the synthesize arm, because the
/// preceding flush already drained it and this one yields nothing. Both are
/// `[0x00]` on the wire, and that octet is the invariant — not the flush rank,
/// the backend status, or the byte count before the transform.
#[test]
fn an_empty_final_fragment_is_the_rfc_octet_by_either_route() {
    // Fresh: the empty final is the only fragment.
    let mut fresh = takeover_encoder();
    let alone = stream(&mut fresh, &[b""]);
    assert_eq!(alone, vec![EMPTY_MESSAGE.to_vec()], "a fresh stream's empty final");

    // After a committed non-final, whose flush has already drained the
    // compressor.
    let mut warmed = takeover_encoder();
    let sequence = stream(&mut warmed, &[b"a fragment with bytes", b""]);
    assert_eq!(
        sequence.last().expect("a final fragment").as_slice(),
        EMPTY_MESSAGE,
        "an empty final after a committed fragment"
    );
    assert_eq!(
        Verifier::new().accept(&on_the_wire(&sequence)).expect("a valid stream"),
        b"a fragment with bytes",
        "the empty final adds no plaintext"
    );

    // And the history the message left is still the peer's: a second,
    // history-dependent message stays aligned on a shared inflater.
    let mut peer = Verifier::new();
    let mut encoder = takeover_encoder();
    let first = stream(&mut encoder, &[b"repeated payload", b""]);
    assert_eq!(peer.accept(&on_the_wire(&first)).expect("valid"), b"repeated payload");
    let second = send(&mut encoder, b"repeated payload");
    assert_eq!(peer.accept(&second).expect("valid"), b"repeated payload");
    assert!(
        second.len() < first.concat().len(),
        "the second message did not reference the streamed message's history: {} vs {}",
        second.len(),
        first.concat().len()
    );
}

// ------------------------------------------------- gate-empty-nonfinal-shapes

/// An empty non-final chunk is a legal boundary, and what it produces depends on
/// where it sits.
///
/// First in a message the compressor has not flushed, so it emits the five-octet
/// trailer; after a committed fragment it emits nothing at all. The pair is the
/// known-positive control that the zero-output row is positional rather than dead
/// code — one arm without the other cannot tell those apart.
#[test]
fn an_empty_non_final_fragment_is_legal_in_both_positions() {
    // First fragment: no flush has happened yet.
    let mut first = takeover_encoder();
    let open = first.begin_streaming_message().expect("a stream");
    let fragment = open.prepare_non_final_fragment(b"").expect("an empty boundary");
    // Five octets, not four: the flush emits an empty block of its own -- the
    // leading `0x00` -- and then the trailer that ends it. `== TRAILER` here
    // would be asserting the wrong shape.
    assert_eq!(
        fragment.as_bytes(),
        [0x00, 0x00, 0x00, 0xff, 0xff],
        "a fresh compressor's empty flush is an empty block plus the trailer"
    );
    let (leading, next) = fragment.commit();
    let mut fragments = vec![leading];
    fragments.push(last_fragment(next, b"payload after an empty start"));
    assert_eq!(
        Verifier::new().accept(&on_the_wire(&fragments)).expect("a valid stream"),
        b"payload after an empty start"
    );

    // Later: the previous fragment's flush already drained the compressor.
    let mut later = takeover_encoder();
    let open = later.begin_streaming_message().expect("a stream");
    let (head, next) = open.prepare_non_final_fragment(b"head").expect("a fragment").commit();
    let empty = next.prepare_non_final_fragment(b"").expect("an empty boundary");
    assert!(empty.as_bytes().is_empty(), "a drained compressor's empty flush produces nothing");
    let (nothing, next) = empty.commit();
    let fragments = vec![head, nothing, last_fragment(next, b" and tail")];
    assert_eq!(
        Verifier::new().accept(&on_the_wire(&fragments)).expect("a valid stream"),
        b"head and tail",
        "committing after the empty continuation frame continues the message"
    );

    // Dropping either shape poisons, the same as any other unresolved state.
    for chunk in [&b""[..], &b"head"[..]] {
        let mut encoder = takeover_encoder();
        let open = encoder.begin_streaming_message().expect("a stream");
        drop(open.prepare_non_final_fragment(chunk).expect("a fragment"));
        assert_eq!(encoder.prepare_message(b"after").expect_err("poisoned"), CodecError::Poisoned);
    }
}

// ------------------------------------------- gate-single-fragment-equivalence

/// A stream whose first fragment is final is `prepare_message` by another name.
///
/// Same bytes and the same history left behind, from the same encoder state. An
/// equivalence check rather than an independent oracle: what it can catch is the
/// refactor that gave the two producers different behaviour for one message.
#[test]
fn a_single_final_fragment_matches_the_whole_message_producer() {
    let payloads: [Vec<u8>; 4] =
        [Vec::new(), b"Hello".to_vec(), vec![b'r'; 30_000], incompressible(30_000, 83)];
    for warm in [false, true] {
        for payload in &payloads {
            let mut whole = takeover_encoder();
            let mut streamed = takeover_encoder();
            if warm {
                // The same history on both sides before the comparison.
                let _ = send(&mut whole, b"a warming message");
                let _ = send(&mut streamed, b"a warming message");
            }

            let expected = send(&mut whole, payload);
            let fragments = stream(&mut streamed, &[payload.as_slice()]);
            assert_eq!(fragments.len(), 1, "one chunk is one fragment");
            assert_eq!(fragments[0], expected, "warm {warm}, {} bytes", payload.len());

            // And the next message from each is identical too, which is the half
            // that says the history matches and not merely the output.
            assert_eq!(
                send(&mut whole, b"the message after"),
                send(&mut streamed, b"the message after"),
                "warm {warm}, {} bytes: the histories diverged",
                payload.len()
            );
        }
    }
}

// ----------------------------------------------------------- gate-poison-states

/// Every unresolved streaming state leaves the encoder poisoned, whether it is
/// dropped or leaked.
///
/// `mem::forget` is the case the design exists for: no `Drop` impl runs, and the
/// compressor is still gone because it lives inside the state rather than being
/// put back by one. The fully committed stream at the end is the known positive —
/// without it this row would pass on an encoder that poisoned unconditionally.
#[test]
fn an_unresolved_streaming_state_poisons_the_encoder() {
    for leak in [false, true] {
        // The stream itself, before any fragment.
        let mut encoder = takeover_encoder();
        let open = encoder.begin_streaming_message().expect("a stream");
        if leak {
            core::mem::forget(open);
        } else {
            drop(open);
        }
        assert_eq!(encoder.begin_streaming_message().expect_err("poisoned"), CodecError::Poisoned);
        assert_eq!(encoder.prepare_message(b"after").expect_err("poisoned"), CodecError::Poisoned);

        // A pending non-final fragment.
        let mut encoder = takeover_encoder();
        let open = encoder.begin_streaming_message().expect("a stream");
        let pending: PreparedNonFinalFragment<'_> =
            open.prepare_non_final_fragment(b"never sent").expect("a fragment");
        if leak {
            core::mem::forget(pending);
        } else {
            drop(pending);
        }
        assert_eq!(encoder.prepare_message(b"after").expect_err("poisoned"), CodecError::Poisoned);

        // A pending final fragment.
        let mut encoder = takeover_encoder();
        let open = encoder.begin_streaming_message().expect("a stream");
        let (_, next) = open.prepare_non_final_fragment(b"head").expect("a fragment").commit();
        let pending: PreparedFinalFragment<'_> =
            next.prepare_final_fragment(b"tail").expect("a final fragment");
        if leak {
            core::mem::forget(pending);
        } else {
            drop(pending);
        }
        assert_eq!(encoder.begin_streaming_message().expect_err("poisoned"), CodecError::Poisoned);
    }

    // The known positive: a stream carried all the way through leaves a working
    // encoder, so the rows above are about resolution and not about streaming.
    let mut encoder = takeover_encoder();
    let fragments = stream(&mut encoder, &[b"head ", b"tail"]);
    assert_eq!(
        Verifier::new().accept(&on_the_wire(&fragments)).expect("a valid stream"),
        b"head tail"
    );
    let _ = encoder.begin_streaming_message().expect("a committed stream leaves the encoder whole");
}

// ---------------------------------------------------------- gate-message-reset

/// Fragment commits never reset; the final commit resets exactly when
/// `no_context_takeover` was negotiated for this direction.
///
/// The discriminator is history dependence, not a flag: the second message
/// repeats the first's payload, so under takeover it must compress smaller and
/// needs the *same* inflater to decode, while under no-context it must not shrink
/// and a *fresh* inflater must accept it. A reset on a non-final commit would
/// show up as the streamed message's own later fragments losing their references.
#[test]
fn the_final_commit_resets_only_under_no_context_takeover() {
    let body = incompressible(6_000, 137);
    let mut repeated = body.clone();
    repeated.extend_from_slice(&body);

    // Takeover: one peer for the whole connection.
    let mut encoder = client_codecs(15, 15, false, EncoderConfig::new());
    let mut peer = Verifier::new();
    let first = stream(&mut encoder, &[&repeated[..3_000], &repeated[3_000..]]);
    assert_eq!(peer.accept(&on_the_wire(&first)).expect("valid"), repeated);
    let second = stream(&mut encoder, &[&repeated[..3_000], &repeated[3_000..]]);
    assert_eq!(peer.accept(&on_the_wire(&second)).expect("valid"), repeated);
    let (first_len, second_len) = (first.concat().len(), second.concat().len());
    assert!(
        second_len < first_len,
        "the second streamed message ignored retained history: {second_len} vs {first_len}"
    );
    // A whole message after a streamed one sees the same history.
    let third = send(&mut encoder, &repeated);
    assert_eq!(peer.accept(&third).expect("valid"), repeated);
    assert!(third.len() < first_len, "a whole message after a stream lost the history");

    // No context takeover: each message stands alone, so a fresh peer decodes
    // the second one.
    let mut encoder = client_codecs(15, 15, true, EncoderConfig::new());
    let first = stream(&mut encoder, &[&repeated[..3_000], &repeated[3_000..]]);
    assert_eq!(Verifier::new().accept(&on_the_wire(&first)).expect("valid"), repeated);
    let second = stream(&mut encoder, &[&repeated[..3_000], &repeated[3_000..]]);
    assert_eq!(
        Verifier::new().accept(&on_the_wire(&second)).expect("a fresh inflater decodes it"),
        repeated
    );
    assert_eq!(
        second.concat().len(),
        first.concat().len(),
        "the reset did not return the second message to the first's size"
    );
}

// ------------------------------------------------------ gate-own-decoder-compat

/// This crate's own decoder accepts the fragments its encoder produces, one
/// frame at a time with the final flag preserved.
///
/// A compatibility row and nothing more: a codec's two halves agreeing cannot
/// tell a correct implementation from two matching mistakes, so the correctness
/// credit belongs to `gate-composite-peer` and its direct `flate2` inflater.
#[test]
fn our_own_decoder_accepts_our_streamed_fragments() {
    const ROOMY: DecompressedLimit = DecompressedLimit::bytes(1 << 20);
    let sequences: [Vec<&[u8]>; 5] = [
        vec![b"single"],
        vec![b"head ", b"middle ", b"tail"],
        vec![b"a message ending empty", b""],
        vec![b"", b"a message starting empty"],
        // A boundary declared after the compressor has already produced output,
        // which is a different position from the first fragment being empty: the
        // flush has bytes behind it rather than none.
        vec![b"head ", b"", b"tail"],
    ];

    for chunks in &sequences {
        let (mut encoder, _) = client_pair(15, 15, false, EncoderConfig::new());
        let (_, mut decoder) = client_pair(15, 15, false, EncoderConfig::new());

        let fragments = stream(&mut encoder, chunks);
        let mut recovered = Vec::new();
        for (i, fragment) in fragments.iter().enumerate() {
            let is_final = i + 1 == fragments.len();
            recovered.extend_from_slice(
                &decoder.decompress(fragment, is_final, ROOMY).expect("our decoder accepts it"),
            );
        }
        assert_eq!(recovered, chunks.concat(), "{} fragments", chunks.len());

        // And a second message on the same pair, so the row covers the history
        // handed across a message boundary rather than one message in isolation.
        let next = send(&mut encoder, b"the message after");
        assert_eq!(
            decoder.decompress(&next, true, ROOMY).expect("the second message"),
            b"the message after"
        );
    }
}

// ------------------------------------------------------------ gate-stream-room

/// Streaming fragments match a differently buffered producer of the same
/// sequence, across the room function's branches.
///
/// The reference is buffered at 1 MiB rather than the crate's per-round room, so
/// agreement is evidence rather than two copies of one buffering strategy. The
/// scope is the whole-message rule applied per chunk: levels 1 through 9 are
/// byte-identical everywhere, and level 0 only below the payload-derived branch,
/// because above it zlib sizes each stored block from the room it was handed.
/// Semantic validity is asserted everywhere regardless.
#[test]
fn streaming_fragments_match_a_differently_buffered_producer() {
    // The room function's own branch edge, per chunk rather than per message.
    const PAYLOAD_ROOM_BAND: usize = 131_008;

    let sizes = [1usize, 5, 4_096, 16_384, 65_535, 65_536, 131_007, 131_072, 200_000];
    // Three octets longer than the largest size, because the middle chunk is
    // taken from just past it.
    let body = incompressible(200_003, 251);
    for level in 0..=9u32 {
        for len in sizes {
            let chunks: Vec<&[u8]> = vec![&body[..len], &body[len..len + 3], &body[..len]];
            let config = EncoderConfig::new().compression_level(level).expect("zlib's domain");
            let ours = stream(&mut client_codecs(15, 15, false, config), &chunks);
            let aligned = direct_stream_aligned(level, 15, &chunks);

            if level > 0 || len <= PAYLOAD_ROOM_BAND {
                for (i, (fragment, reference)) in ours.iter().zip(&aligned).enumerate() {
                    let is_final = i + 1 == ours.len();
                    let expected = if is_final {
                        assert!(reference.ends_with(TRAILER), "level {level}, {len}: no trailer");
                        &reference[..reference.len() - TRAILER.len()]
                    } else {
                        reference.as_slice()
                    };
                    assert_eq!(
                        fragment.len(),
                        expected.len(),
                        "level {level}, {len} bytes, fragment {i}: {} octets against {}",
                        fragment.len(),
                        expected.len()
                    );
                    assert_eq!(fragment.as_slice(), expected, "level {level}, {len}, fragment {i}");
                }
            }

            assert_eq!(
                Verifier::new().accept(&on_the_wire(&ours)).expect("a valid stream"),
                chunks.concat(),
                "level {level}, {len} bytes"
            );
        }
    }
}
