//! The encoder, driven through the public API only.
//!
//! Every compressed result here is decoded by an inflater built directly on
//! `flate2`, never by this crate's `Decoder`: a round trip through one
//! implementation's own two halves cannot tell a correct codec from two matching
//! mistakes. The byte-exact expectations come from RFC 7692's own worked
//! examples, which were published in 2015 and owe nothing to `flate2` or to us.
#![expect(clippy::expect_used, clippy::indexing_slicing, reason = "a panic is how a test reports")]

use flate2::{Compress, Compression, Decompress, FlushCompress, FlushDecompress};
use http::{header::SEC_WEBSOCKET_EXTENSIONS, HeaderMap, HeaderValue};
use permessage_deflate::{
    ClientConfig, ClientOffer, CodecError, Decoder, Encoder, EncoderConfig, PmdComposition,
    ServerConfig, ServerHandshake,
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
const fn require_send<T: Send>() {}
const _: () = require_send::<Encoder>();
const _: () = require_send::<Decoder>();

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

    /// One complete message, with the stripped trailer fed back.
    fn accept(&mut self, wire: &[u8]) -> Result<Vec<u8>, String> {
        let mut fed = wire.to_vec();
        fed.extend_from_slice(TRAILER);
        let mut out = Vec::new();
        let mut input = fed.as_slice();
        while !input.is_empty() {
            out.reserve(1 << 16);
            let before = (self.0.total_in(), self.0.total_out());
            self.0
                .decompress_vec(input, &mut out, FlushDecompress::None)
                .map_err(|error| error.to_string())?;
            let consumed = usize::try_from(self.0.total_in() - before.0).expect("fits");
            let produced = self.0.total_out() - before.1;
            input = &input[consumed..];
            if consumed == 0 && produced == 0 {
                break;
            }
        }
        Ok(out)
    }
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
        .0
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

/// A host may split the returned payload anywhere; the encoder never sees a
/// fragment.
///
/// RFC 7692 section 7.2.1: "An endpoint fragments a compressed message by
/// splitting the result of running this algorithm." The adjacent MUST NOT — that
/// `00 00 ff ff` is not removed from non-final fragments — governs the other
/// strategy, where a host calls an encoder once per fragment, and nothing here
/// enters it: the trailer is removed once, from the complete result.
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
