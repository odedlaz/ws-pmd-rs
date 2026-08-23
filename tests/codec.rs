//! The decoder, driven through the public API only.
//!
//! The compressed inputs come either from RFC 7692's own worked examples or from
//! a peer built directly on `flate2` in this file, never from this crate's
//! encoder. A round trip through one implementation's own two halves cannot tell
//! a correct codec from two matching mistakes.
#![expect(
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "a panic is how a test reports"
)]

use flate2::{Compress, Compression, FlushCompress, Status};
use http::{header::SEC_WEBSOCKET_EXTENSIONS, HeaderMap, HeaderValue};
use permessage_deflate::{
    ClientConfig, ClientOffer, CodecError, Decoder, DecompressedLimit, PmdComposition,
};

/// RFC 7692 section 7.2.1: every compressed message has this stripped from its
/// tail, and a decoder must feed it back to reach the end of the message.
const TRAILER: &[u8] = &[0x00, 0x00, 0xff, 0xff];

/// Big enough that no bounds test reaches it by accident.
const ROOMY: DecompressedLimit = DecompressedLimit::bytes(1 << 20);

/// A client decoder for a response the server sent, so the agreement under test
/// is one the negotiation half actually produced.
fn decoder_for(response: &[u8]) -> Decoder {
    let mut request = HeaderMap::new();
    let offer = ClientOffer::install(ClientConfig::new(), &mut request).expect("fresh map");
    let mut headers = HeaderMap::new();
    headers.append(
        SEC_WEBSOCKET_EXTENSIONS,
        HeaderValue::from_bytes(response).expect("test input is a valid header value"),
    );
    offer
        .seal(&request)
        .expect("the offer is unchanged")
        .finish(&headers, PmdComposition::Compatible)
        .expect("the response is legal")
        .expect("the server selected it")
        .into_decoder()
}

fn plain_decoder() -> Decoder {
    decoder_for(b"permessage-deflate")
}

/// An independent RFC 7692 peer: raw DEFLATE, `Z_SYNC_FLUSH`, trailer stripped.
struct Peer(Compress);

impl Peer {
    fn new(window_bits: u8) -> Self {
        Self(Compress::new_with_window_bits(Compression::default(), false, window_bits))
    }

    /// A peer that emits stored blocks, which a real one does whenever deflating
    /// would expand the data.
    ///
    /// Its first wire byte is `0x00`, and that byte is what separates a corrupt
    /// inflater state from a rejected one: the trailer misparsed at the start of
    /// a stream leaves one byte of a length field outstanding, so the next
    /// message's first byte decides whether the length checks out and 65,280
    /// bytes of nonsense are copied, or the stream is rejected outright.
    fn uncompressed() -> Self {
        Self(Compress::new_with_window_bits(Compression::none(), false, 15))
    }

    /// One complete message: the trailer the RFC strips is stripped.
    fn send(&mut self, payload: &[u8]) -> Vec<u8> {
        let mut wire = self.flush(payload);
        wire.truncate(wire.len() - TRAILER.len());
        wire
    }

    /// One message split at a flush boundary, which is how a peer produces a
    /// fragmented message: the host splits the compressed bytes, and only the
    /// tail of the last fragment loses the trailer.
    fn send_in_two(&mut self, head: &[u8], tail: &[u8]) -> (Vec<u8>, Vec<u8>) {
        (self.flush(head), self.send(tail))
    }

    /// Compress and `Z_SYNC_FLUSH`, trailer included.
    fn flush(&mut self, payload: &[u8]) -> Vec<u8> {
        let mut output = Vec::new();
        let mut input = payload;
        while !input.is_empty() {
            output.reserve(4096);
            let before = (self.0.total_in(), self.0.total_out());
            self.0.compress_vec(input, &mut output, FlushCompress::None).expect("peer compresses");
            let consumed = usize::try_from(self.0.total_in() - before.0).expect("fits");
            if consumed == 0 && self.0.total_out() == before.1 {
                break;
            }
            input = &input[consumed..];
        }
        loop {
            output.reserve(4096);
            let before = self.0.total_out();
            self.0.compress_vec(&[], &mut output, FlushCompress::Sync).expect("peer flushes");
            if self.0.total_out() == before {
                break;
            }
        }
        assert!(output.ends_with(TRAILER), "the peer must emit a sync-flush trailer");
        assert!(input.is_empty(), "the whole payload must reach the wire");
        output
    }
}

/// A bare finished RFC 1951 stream: steps 2 and 3 of RFC 7692 section 7.2.1 have
/// not been run on it, so it is *not* a conforming compressed message. Only the
/// rejection row may use this directly.
fn bare_finished_stream(plain: &[u8]) -> Vec<u8> {
    let mut ender = Compress::new_with_window_bits(Compression::best(), false, 15);
    let mut wire = vec![0u8; plain.len() * 2 + 64];
    assert_eq!(
        ender.compress(plain, &mut wire, FlushCompress::Finish).expect("one buffer"),
        Status::StreamEnd,
        "the whole stream must finish"
    );
    wire.truncate(usize::try_from(ender.total_out()).expect("fits"));
    wire
}

/// One conforming message from a peer that flushed with `BFINAL` set.
///
/// RFC 7692 section 7.2.1 runs on every compressed message: the `BFINAL` block is
/// padded to a byte boundary, step 2 appends an empty `BTYPE=00` block because the
/// data does not already end with one, and step 3 removes that block's four
/// octets. What is left is the single `0x00` octet section 7.2.3.4 calls
/// "necessary to allow the payload to be decompressed in the same manner as
/// messages flushed using DEFLATE blocks with BFINAL unset" -- the same shape as
/// the RFC's own `f3 48 cd c9 c9 07 00 00` vector.
fn bfinal_message(plain: &[u8]) -> Vec<u8> {
    let mut wire = bare_finished_stream(plain);
    wire.push(0x00);
    wire
}

/// A payload long enough that a corrupted inflater state shows up as wrong bytes
/// rather than surviving by being too short to matter.
fn structured_payload(len: u32) -> Vec<u8> {
    (0..len).map(|i| u8::try_from(i.wrapping_mul(31) % 251).expect("under 251")).collect()
}

// -------------------------------------------------------- validate-codec-vectors

/// RFC 7692 section 7.2.3.1. The endpoint compresses "Hello" into one DEFLATE
/// block and flushes with an empty no-compression block, giving
/// `f2 48 cd c9 c9 07 00 00 00 ff ff`; stripping `00 00 ff ff` from the tail
/// leaves the message payload.
#[test]
fn rfc_7692_7_2_3_1_one_deflate_block() {
    const PAYLOAD: &[u8] = &[0xf2, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x00];
    let decoded = plain_decoder().decompress(PAYLOAD, true, ROOMY).expect("a legal stream");
    assert_eq!(decoded, b"Hello");
}

/// RFC 7692 section 7.2.3.1, continued: the same compressed data split into
/// fragments of 3 and 4 octets. The RFC's frames are `41 03 f2 48 cd` and
/// `80 04 c9 c9 07 00`; the two-byte WebSocket headers are the host's business,
/// so only the payloads reach the decoder. RSV1 rides on the first frame alone.
#[test]
fn rfc_7692_7_2_3_1_split_across_two_fragments() {
    let mut decoder = plain_decoder();
    let mut got = decoder.decompress(&[0xf2, 0x48, 0xcd], false, ROOMY).expect("first");
    got.extend(decoder.decompress(&[0xc9, 0xc9, 0x07, 0x00], true, ROOMY).expect("last"));
    assert_eq!(got, b"Hello");
}

/// RFC 7692 section 7.2.3.4. A peer without a no-compression flush can flush
/// with `BFINAL` set instead: seven octets carry "Hello" with `BFINAL` = 1, and
/// the trailing `0x00` is there so the payload decompresses the same way as one
/// flushed with `BFINAL` unset.
#[test]
fn rfc_7692_7_2_3_4_a_block_with_bfinal_set() {
    const PAYLOAD: &[u8] = &[0xf3, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x00, 0x00];
    let decoded = plain_decoder().decompress(PAYLOAD, true, ROOMY).expect("a legal stream");
    assert_eq!(decoded, b"Hello");
}

/// RFC 7692 section 7.2.3.5: two or more DEFLATE blocks may be used in one
/// message.
#[test]
fn rfc_7692_7_2_3_5_two_deflate_blocks_in_one_message() {
    const PAYLOAD: &[u8] =
        &[0xf2, 0x48, 0x05, 0x00, 0x00, 0x00, 0xff, 0xff, 0xca, 0xc9, 0xc9, 0x07, 0x00];
    let decoded = plain_decoder().decompress(PAYLOAD, true, ROOMY).expect("a legal stream");
    assert_eq!(decoded, b"Hello");
}

/// A `BFINAL` block ends the DEFLATE stream, so the inflater is finished and
/// every later message would decode to nothing unless it is restarted. This is
/// the row that fails if the `StreamEnd` reset goes: the first message passes
/// either way, and only the second one discriminates.
#[test]
fn a_message_after_a_bfinal_message_still_decodes() {
    const BFINAL_HELLO: &[u8] = &[0xf3, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x00, 0x00];
    let mut decoder = plain_decoder();
    assert_eq!(decoder.decompress(BFINAL_HELLO, true, ROOMY).expect("first"), b"Hello");

    // A peer that ended its stream must start a new one, which cannot reference
    // the window it just closed, so a fresh compressor is the honest mirror.
    let payload = b"the quick brown fox jumps over the lazy dog".to_vec();
    let wire = Peer::new(15).send(&payload);
    let second = decoder.decompress(&wire, true, ROOMY).expect("second");
    assert_eq!(second, payload, "the inflater must have restarted after BFINAL");
}

/// The row above uses the RFC's own five-octet payload, short enough to survive a
/// corrupted inflater either way. This one drives a longer producer and checks the
/// state a `BFINAL` message leaves behind, with the next message in the form that
/// tells corruption from rejection.
#[test]
fn a_message_after_a_byte_aligned_bfinal_message_decodes_exactly() {
    let mut decoder = plain_decoder();
    let first = b"a peer that ends its stream on a byte boundary".to_vec();
    assert_eq!(decoder.decompress(&bfinal_message(&first), true, ROOMY).expect("first"), first);

    let payload = structured_payload(1024);
    let second = Peer::uncompressed().send(&payload);
    assert_eq!(second.first(), Some(&0x00), "the input that tells corruption from rejection");
    assert_eq!(
        decoder.decompress(&second, true, ROOMY).expect("second"),
        payload,
        "the message after a byte-aligned BFINAL must arrive byte-exact"
    );
}

/// RFC 7692 section 7.2.1: "An endpoint MAY use both DEFLATE blocks with the
/// BFINAL bit set to 0 and DEFLATE blocks with the BFINAL bit set to 1", and
/// "The next DEFLATE block follows the padded data if any" -- in the same
/// message. So a stream ending is a block boundary, not a message boundary, and
/// a decoder that stops there drops the rest of a conforming message in silence.
///
/// The second stream is compressed by a fresh peer, because a peer that closed
/// its stream cannot reference the window it closed.
#[test]
fn rfc_7692_7_2_1_a_second_stream_follows_a_bfinal_block_in_one_message() {
    let mut wire = bare_finished_stream(b"Hello");
    wire.extend(Peer::new(15).send(b"World"));
    let decoded = plain_decoder().decompress(&wire, true, ROOMY).expect("a legal message");
    assert_eq!(decoded, b"HelloWorld", "everything after the BFINAL block belongs to it");
}

/// The same message, split at the stream boundary. Section 7.2.1 says the removal
/// of `00 00 ff ff` "MUST NOT be done" for non-final fragments, so the first
/// fragment is the padded `BFINAL` block exactly as it stands.
#[test]
fn rfc_7692_7_2_1_a_second_stream_follows_a_bfinal_block_across_a_fragment() {
    let mut decoder = plain_decoder();
    let mut got = decoder
        .decompress(&bare_finished_stream(b"Hello"), false, ROOMY)
        .expect("the fragment that ends the stream");
    got.extend(decoder.decompress(&Peer::new(15).send(b"World"), true, ROOMY).expect("the rest"));
    assert_eq!(got, b"HelloWorld", "a stream boundary is not a fragment boundary either");
}

/// Steps 2 and 3 of section 7.2.1 are mandatory, so a bare finished RFC 1951
/// stream is malformed input however well it decompresses. Saying so is the only
/// answer that neither corrupts state nor truncates a conforming message: before
/// this, the four octets went into an inflater at the start of a stream and the
/// peer's own framing was delivered as the *next* message's content -- 1,033
/// bytes for a 1,024-byte payload, `Ok`, no error and no poisoning.
///
/// Both lengths, because a short stream ends on the loop's first pass, where the
/// position was never opened and clearing it at the stream end proves nothing. A
/// stream long enough to refill the scratch buffer opens it first, and that is
/// the one that needs the stream end to take it back.
#[test]
fn a_bare_finished_stream_is_rejected() {
    for plain in [b"no appended empty block".to_vec(), structured_payload(100_000)] {
        let mut decoder = plain_decoder();
        assert_eq!(
            decoder.decompress(&bare_finished_stream(&plain), true, ROOMY),
            Err(CodecError::InvalidStream),
            "{} bytes: the mandatory post-BFINAL block never arrived",
            plain.len()
        );
        assert_eq!(
            decoder.decompress(&Peer::new(15).send(b"anything"), true, ROOMY),
            Err(CodecError::Poisoned),
            "and every failure here is terminal"
        );
    }
}

/// A conforming `BFINAL` message whose mandatory tail lands in one fragment and
/// whose message ends in the next. RFC 6455 section 5.4 permits that: "A sender
/// MAY create fragments of any size for non-control frames", an empty final
/// continuation frame included.
///
/// The stream ends in the earlier call, so whatever the decoder records about
/// where the inflater stands has to survive the fragment boundary -- and the
/// mandatory `0x00` that arrives before it is what licenses the trailer.
#[test]
fn a_stream_that_ends_before_the_final_fragment_leaves_the_next_message_exact() {
    let mut decoder = plain_decoder();
    let first = b"a peer that ends its stream on a byte boundary".to_vec();
    let mut got =
        decoder.decompress(&bfinal_message(&first), false, ROOMY).expect("first fragment");
    got.extend(decoder.decompress(&[], true, ROOMY).expect("an empty final fragment"));
    assert_eq!(got, first, "the message whose stream ended early still arrives whole");

    let payload = structured_payload(1024);
    let second = Peer::uncompressed().send(&payload);
    assert_eq!(second.first(), Some(&0x00), "the input that tells corruption from rejection");
    assert_eq!(
        decoder.decompress(&second, true, ROOMY).expect("second"),
        payload,
        "a stream that ended on an earlier fragment must leave the position with it"
    );
}

/// A `BFINAL` message long enough to span several backend calls, so the stream
/// ends part-way through the loop rather than on its first pass. Every other
/// `BFINAL` row here finishes in one call -- and a real one is usually the long
/// kind.
#[test]
fn a_long_bfinal_message_leaves_the_next_message_exact() {
    let mut decoder = plain_decoder();
    let first = structured_payload(100_000);
    assert_eq!(decoder.decompress(&bfinal_message(&first), true, ROOMY).expect("first"), first);

    let payload = structured_payload(1024);
    let second = Peer::uncompressed().send(&payload);
    assert_eq!(second.first(), Some(&0x00), "the input that tells corruption from rejection");
    assert_eq!(
        decoder.decompress(&second, true, ROOMY).expect("second"),
        payload,
        "a stream that ended mid-fragment must leave the position with it"
    );
}

/// The mandatory tail may itself land in a later fragment: section 7.2.1
/// fragments a message by "splitting the result of running this algorithm", so
/// the octet step 3 leaves behind can arrive on its own. Nothing observes that a
/// later fragment is what opened the stream unless the earlier one closed it.
#[test]
fn rfc_7692_7_2_1_the_mandatory_tail_may_arrive_in_a_later_fragment() {
    let mut decoder = plain_decoder();
    let mut got = decoder
        .decompress(&bare_finished_stream(b"Hello"), false, ROOMY)
        .expect("the fragment that ends the stream");
    got.extend(decoder.decompress(&[0x00], true, ROOMY).expect("the fragment carrying the tail"));
    assert_eq!(got, b"Hello", "the tail licenses the trailer wherever it arrives");
}

/// And the same split with the tail nowhere in the message, which is Dario's
/// probe shape once its polarity is corrected: a bare finished stream in a
/// non-final fragment and nothing after it. The missing-tail answer has to hold
/// across a fragment boundary too, not only within one call.
#[test]
fn a_bare_finished_stream_is_rejected_across_a_fragment_boundary() {
    let mut decoder = plain_decoder();
    decoder
        .decompress(&bare_finished_stream(b"no appended empty block"), false, ROOMY)
        .expect("the fragment itself decodes");
    assert_eq!(
        decoder.decompress(&[], true, ROOMY),
        Err(CodecError::InvalidStream),
        "the mandatory tail arrived in no fragment at all"
    );
}

/// A message that carries no bytes at all began no block, so the four octets step
/// 3 removed cannot belong to it. RFC 7692 section 7.2.3.6 has an endpoint send
/// the payload `0x00` for an empty fragment -- one octet, not none -- so this is
/// the same missing-tail condition as a bare finished stream, and it takes the
/// same answer.
#[test]
fn an_empty_message_is_rejected() {
    assert_eq!(
        plain_decoder().decompress(&[], true, ROOMY),
        Err(CodecError::InvalidStream),
        "no block begun, so nothing for the stripped octets to complete"
    );
}

/// And after a `no_context_takeover` reinitialisation, which is the other place
/// the inflater goes back to the start of a stream. A decoder that reinitialised
/// there without putting the position back would take the next message's stripped
/// octets into a fresh inflater, and this is the only shape that observes it --
/// any message carrying bytes opens the stream again before the trailer is fed.
#[test]
fn an_empty_message_is_rejected_after_a_no_takeover_reinitialisation() {
    let mut decoder = decoder_for(b"permessage-deflate; server_no_context_takeover");
    let first = b"a conforming message, so the reinitialisation runs".to_vec();
    assert_eq!(decoder.decompress(&Peer::new(15).send(&first), true, ROOMY).expect("first"), first);
    assert_eq!(
        decoder.decompress(&[], true, ROOMY),
        Err(CodecError::InvalidStream),
        "the reinitialisation put the inflater back at a stream start"
    );
}

/// A message that refills the scratch buffer many times over, which is what
/// reproduces the abort in the `flate2` versions `Cargo.toml` excludes,
/// whenever one of them is the backend resolved. It does not defend that floor:
/// as `Cargo.toml` records, the locked gate resolves the `Cargo.lock` entry
/// whatever the declared requirement says, so what excludes those versions is
/// the requirement itself.
#[test]
fn a_message_spanning_many_scratch_refills_decodes() {
    let payload: Vec<u8> =
        (0..(1usize << 19)).map(|i| u8::try_from(i % 251).expect("under 251")).collect();
    let wire = Peer::new(15).send(&payload);
    let decoded = plain_decoder().decompress(&wire, true, ROOMY).expect("a long legal message");
    assert_eq!(decoded.len(), payload.len(), "every byte must arrive");
    assert_eq!(decoded, payload);
}

// ------------------------------------------------------------- validate-bounds

/// The ceiling is exact on both sides. These two rows are the whole contract:
/// `n` bytes must arrive whole, and byte `n + 1` must not arrive at all.
#[test]
fn a_message_is_accepted_at_the_limit() {
    let payload = vec![b'x'; 4000];
    let wire = Peer::new(15).send(&payload);
    let decoded = plain_decoder()
        .decompress(&wire, true, DecompressedLimit::bytes(payload.len()))
        .expect("exactly at the limit must be accepted");
    assert_eq!(decoded, payload, "and it must arrive whole");
}

#[test]
fn a_message_is_rejected_one_byte_over_the_limit() {
    let payload = vec![b'x'; 4000];
    let wire = Peer::new(15).send(&payload);
    let limit = payload.len() - 1;
    match plain_decoder().decompress(&wire, true, DecompressedLimit::bytes(limit)) {
        // `size > limit` would restate the condition the error is built from,
        // and echoing `limit` back asserts an input. The claim with content is
        // that detection happens on the first byte past the ceiling.
        Err(CodecError::MessageTooLong { size, limit: reported }) => {
            assert_eq!(size, limit + 1, "detection must be one byte past the ceiling");
            assert_eq!(reported, limit, "the error names the ceiling that was in force");
        }
        other => panic!("one byte over must be MessageTooLong, got {other:?}"),
    }
}

/// 66 compressed bytes for 50 KiB of zeroes. The bytes are the audited fixture
/// from tungstenite `705e0cbb:src/extensions/compression/deflate/mod.rs:443-457`,
/// chosen so the compressed form lands on a byte boundary and can be repeated to
/// build an arbitrarily large message. The guard has to fire during inflate,
/// which the reported size is what proves: one byte over, not one chunk over.
#[test]
fn a_compression_bomb_is_stopped_during_inflate() {
    const BOMB: &[u8; 66] = &[
        0xec, 0xc1, 0x31, 0x01, 0x00, 0x00, 0x00, 0xc2, 0xa0, 0xf5, 0x4f, 0x6d, 0x0b, 0x2f, 0xa0,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0xe0, 0x6f,
    ];
    let mut wire = BOMB.to_vec();
    wire.push(0x00);

    let limit = 8 * 1024;
    // Both fragment kinds. The ceiling is enforced during inflate, not at the
    // end of a message, so a decoder that only checked on the final fragment
    // would materialise the whole bomb first and pass a final-only row.
    for final_fragment in [true, false] {
        let mut decoder = plain_decoder();
        match decoder.decompress(&wire, final_fragment, DecompressedLimit::bytes(limit)) {
            Err(CodecError::MessageTooLong { size, limit: reported }) => {
                assert_eq!(size, limit + 1, "a bomb must be stopped as it crosses, not after");
                assert_eq!(reported, limit);
            }
            other => panic!("final_fragment={final_fragment}: must be rejected, got {other:?}"),
        }
        assert_eq!(
            decoder.decompress(&wire, true, ROOMY),
            Err(CodecError::Poisoned),
            "final_fragment={final_fragment}: the direction is terminal"
        );
    }
}

/// The ceiling is per message, not per fragment. Without the running total a
/// fragmented message could deliver the full allowance again on every fragment.
#[test]
fn the_ceiling_counts_bytes_delivered_by_earlier_fragments() {
    let (head, tail) = Peer::new(15).send_in_two(&[b'a'; 3000], &[b'b'; 3000]);
    let mut decoder = plain_decoder();
    let limit = DecompressedLimit::bytes(4000);

    assert_eq!(
        decoder.decompress(&head, false, limit).expect("3000 of 4000 fits").len(),
        3000,
        "the first fragment must land inside the allowance"
    );

    match decoder.decompress(&tail, true, limit) {
        Err(CodecError::MessageTooLong { size, limit: reported }) => {
            assert_eq!(reported, 4000);
            assert_eq!(size, 4001, "the earlier fragment's 3000 bytes must still count");
        }
        other => panic!("the total must span fragments, got {other:?}"),
    }
}

/// A fragmented message that stays inside the allowance must arrive whole, or
/// the row above could pass on a decoder that simply refuses second fragments.
#[test]
fn a_fragmented_message_inside_the_ceiling_arrives_whole() {
    let (head, tail) = Peer::new(15).send_in_two(&[b'a'; 3000], &[b'b'; 3000]);
    let mut decoder = plain_decoder();
    let limit = DecompressedLimit::bytes(6000);

    let mut got = decoder.decompress(&head, false, limit).expect("first fragment");
    got.extend(decoder.decompress(&tail, true, limit).expect("last fragment"));

    let mut expected = vec![b'a'; 3000];
    expected.extend(std::iter::repeat_n(b'b', 3000));
    assert_eq!(got, expected);
}

/// A fresh message starts from zero, or a long-lived connection would slowly
/// exhaust its own allowance.
#[test]
fn the_running_total_resets_at_the_end_of_a_message() {
    let payload = vec![b'z'; 3000];
    let mut peer = Peer::new(15);
    let mut decoder = plain_decoder();
    let limit = DecompressedLimit::bytes(4000);

    for message in 0..4 {
        let wire = peer.send(&payload);
        let got = decoder.decompress(&wire, true, limit).unwrap_or_else(|error| {
            panic!("message {message} must not inherit an earlier total: {error}")
        });
        assert_eq!(got.len(), 3000);
    }
}

/// The host passes its current ceiling on every call, so a runtime configuration
/// change is obeyed rather than frozen at negotiation. This row lowers it
/// between messages; `a_ceiling_raised_between_fragments_is_honoured` is the
/// other direction, and it is the harder one -- a decoder that keeps the
/// smallest ceiling it has seen passes every row here.
#[test]
fn a_ceiling_change_between_messages_is_observed() {
    let payload = vec![b'q'; 3000];
    let mut peer = Peer::new(15);
    let mut decoder = plain_decoder();

    let wire = peer.send(&payload);
    assert!(
        decoder.decompress(&wire, true, DecompressedLimit::bytes(4000)).is_ok(),
        "3000 bytes fit under 4000"
    );

    let wire = peer.send(&payload);
    let tightened = decoder.decompress(&wire, true, DecompressedLimit::bytes(2000));
    assert!(
        matches!(tightened, Err(CodecError::MessageTooLong { limit: 2000, .. })),
        "the lowered ceiling must bite, got {tightened:?}"
    );
}

/// Zero is a legal ceiling and means what it says: nothing may be produced. An
/// empty message produces nothing, so it is the one thing that still passes.
#[test]
fn a_zero_ceiling_admits_an_empty_message_and_nothing_else() {
    let none = DecompressedLimit::bytes(0);
    let empty = Peer::new(15).send(b"");
    assert_eq!(
        plain_decoder().decompress(&empty, true, none).expect("nothing is within nothing"),
        b"",
    );

    let wire = Peer::new(15).send(b"x");
    assert!(
        matches!(
            plain_decoder().decompress(&wire, true, none),
            Err(CodecError::MessageTooLong { size: 1, limit: 0 })
        ),
        "one byte is already over a ceiling of zero"
    );
}

/// Every window RFC 7692 admits on the wire, including the 8 that flate2 will
/// not construct an inflater for. The peer compresses at the width it agreed
/// to; this side widens to 9 only where flate2's floor forces it, and a wider
/// inflater accepts every stream a narrower compressor emits.
#[test]
fn every_negotiated_peer_window_round_trips() {
    let payload = b"the quick brown fox jumps over the lazy dog, twice over".repeat(4);
    for bits in 8..=15u8 {
        let response = format!("permessage-deflate; server_max_window_bits={bits}");
        let mut decoder = decoder_for(response.as_bytes());
        // 8 is legal to agree to and impossible to build, so the peer uses 9.
        let wire = Peer::new(bits.max(9)).send(&payload);
        let got = decoder
            .decompress(&wire, true, ROOMY)
            .unwrap_or_else(|error| panic!("window {bits} must round trip: {error}"));
        assert_eq!(got, payload, "window {bits}");
    }
}

// ------------------------------------------------------------------- poisoning

/// A failed direction stays failed. The peer's compressor has moved on either
/// way, so resuming would hand the host plausible wrong bytes; the second call
/// must say the direction is dead rather than repeat the original complaint.
#[test]
fn an_over_long_message_poisons_the_decoder() {
    let payload = vec![b'x'; 4000];
    let mut peer = Peer::new(15);
    let mut decoder = plain_decoder();

    let wire = peer.send(&payload);
    assert!(matches!(
        decoder.decompress(&wire, true, DecompressedLimit::bytes(10)),
        Err(CodecError::MessageTooLong { .. })
    ));

    let wire = peer.send(&payload);
    assert_eq!(
        decoder.decompress(&wire, true, ROOMY),
        Err(CodecError::Poisoned),
        "a roomy ceiling must not revive a failed direction"
    );
}

#[test]
fn an_invalid_stream_poisons_the_decoder() {
    let mut decoder = plain_decoder();
    let error = decoder
        .decompress(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff], true, ROOMY)
        .expect_err("not a DEFLATE stream");
    assert_eq!(error, CodecError::InvalidStream);

    let wire = Peer::new(15).send(b"Hello");
    assert_eq!(decoder.decompress(&wire, true, ROOMY), Err(CodecError::Poisoned));
}

// -------------------------------------------------------------------- takeover

/// With takeover the peer keeps its window across messages and the second
/// "Hello" is a back-reference; the decoder must have kept the matching history
/// to resolve it. RFC 7692 section 7.2.3.2 gives both payloads: `f2 48 cd c9 c9
/// 07 00` for the first message, and `f2 00 11 00 00` for the second when the
/// window is shared.
#[test]
fn peer_takeover_resolves_a_back_reference_into_the_previous_message() {
    let mut decoder = plain_decoder();
    assert_eq!(
        decoder
            .decompress(&[0xf2, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x00], true, ROOMY)
            .expect("first"),
        b"Hello",
    );
    assert_eq!(
        decoder.decompress(&[0xf2, 0x00, 0x11, 0x00, 0x00], true, ROOMY).expect("second"),
        b"Hello",
        "the back-reference must resolve against the retained window",
    );
}

/// `server_no_context_takeover` in the response means the peer drops its history
/// after each message, so this side must drop the matching window. Feeding the
/// shared-window second payload from section 7.2.3.2 is how that becomes
/// observable: it can only decode against history this decoder must not have.
#[test]
fn peer_no_context_takeover_drops_the_window_between_messages() {
    let mut decoder = decoder_for(b"permessage-deflate; server_no_context_takeover");
    assert_eq!(
        decoder
            .decompress(&[0xf2, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x00], true, ROOMY)
            .expect("first"),
        b"Hello",
    );
    // Observed, not predicted: a back-reference into a window that is gone
    // fails the stream. `!matches!(.., Ok(b"Hello"))` would also have accepted
    // corrupt plaintext, or an error this decoder had inherited from earlier.
    assert_eq!(
        decoder.decompress(&[0xf2, 0x00, 0x11, 0x00, 0x00], true, ROOMY),
        Err(CodecError::InvalidStream),
    );
    assert_eq!(
        decoder.decompress(&[0xf2, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x00], true, ROOMY),
        Err(CodecError::Poisoned),
        "a broken stream is terminal for the direction"
    );
}

/// The other half: dropping the window must not break messages that never
/// reference across one. Without this, a decoder that reset at the wrong point
/// -- before feeding the trailer rather than after -- still fails the
/// back-reference above and looks correct.
#[test]
fn a_no_takeover_decoder_reads_independent_messages_exactly() {
    let mut decoder = decoder_for(b"permessage-deflate; server_no_context_takeover");
    for payload in [&b"first message, compressible, first message"[..], b"and a second one"] {
        // A fresh peer per message is what a no-takeover sender produces: each
        // message starts from an empty window on both sides.
        let wire = Peer::new(15).send(payload);
        assert_eq!(
            decoder.decompress(&wire, true, ROOMY).expect("an independent message decodes"),
            payload
        );
    }
}

/// The same independence, at a width that reinitialises by rebuilding instead
/// of by resetting.
///
/// `reset` keeps the negotiated window only at 15, so every narrower agreement
/// takes the other route -- and no other row in this file negotiates a narrow
/// window and `no_context_takeover` together, which left that route unexecuted.
/// What this proves is that the rebuilt inflater works and drops its history,
/// not which route ran: a conforming width-9 message decodes through a
/// default-width inflater just as well. Route selection is the C arm's.
#[test]
fn a_narrow_no_takeover_decoder_reads_independent_messages_exactly() {
    let mut decoder =
        decoder_for(b"permessage-deflate; server_no_context_takeover; server_max_window_bits=9");
    for payload in [&b"first message, compressible, first message"[..], b"and a second one"] {
        let wire = Peer::new(9).send(payload);
        assert_eq!(
            decoder.decompress(&wire, true, ROOMY).expect("an independent message decodes"),
            payload
        );
    }
}

/// A decoder that remembers the smallest ceiling seen during a message honours
/// every reduction, resets on final, and passes every other row in this file --
/// while illegally rejecting a host that raises its capacity mid-message. The
/// ceiling is read fresh on each call, so the raise has to be obeyed too.
#[test]
fn a_ceiling_raised_between_fragments_is_honoured() {
    let (head, tail) = Peer::new(15).send_in_two(&vec![b'a'; 3000], &vec![b'b'; 3000]);
    let mut decoder = plain_decoder();

    let first = decoder
        .decompress(&head, false, DecompressedLimit::bytes(4000))
        .expect("3000 of 4000 fits");
    assert_eq!(first.len(), 3000);

    let second = decoder
        .decompress(&tail, true, DecompressedLimit::bytes(6000))
        .expect("the raised ceiling admits the rest of the message");
    assert_eq!(second.len(), 3000, "all 6000 bytes of the message must be delivered");
}

/// `MessageTooLong.size` is one past `limit` only while the ceiling still
/// exceeds what this message already delivered. Two rows, because a single one
/// cannot separate "one past the ceiling" from "one past the delivery" — and
/// the pair is what makes `size - limit` unusable, which the variant now says.
#[test]
fn a_lowered_ceiling_above_the_delivery_stops_one_past_the_ceiling() {
    let mut peer = Peer::new(15);
    let (head, tail) = peer.send_in_two(&vec![b'a'; 3000], &vec![b'b'; 3000]);
    let mut decoder = plain_decoder();
    let delivered = decoder.decompress(&head, false, ROOMY).expect("the first fragment fits");
    assert_eq!(delivered.len(), 3000);
    let error = decoder
        .decompress(&tail, true, DecompressedLimit::bytes(4000))
        .expect_err("the message runs past the lowered ceiling");
    assert_eq!(error, CodecError::MessageTooLong { size: 4001, limit: 4000 });
}

#[test]
fn a_lowered_ceiling_below_the_delivery_stops_one_past_the_delivery() {
    let mut peer = Peer::new(15);
    let (head, tail) = peer.send_in_two(&vec![b'a'; 3000], &vec![b'b'; 3000]);
    let mut decoder = plain_decoder();
    let delivered = decoder.decompress(&head, false, ROOMY).expect("the first fragment fits");
    assert_eq!(delivered.len(), 3000);
    let error = decoder
        .decompress(&tail, true, DecompressedLimit::bytes(2000))
        .expect_err("the ceiling is already below what was delivered");
    // 3001, not 2001: the ceiling fell under the delivery, so `size - limit` is
    // 1001 here and 1 in the row above. A host cannot read a chunk size off it.
    assert_eq!(error, CodecError::MessageTooLong { size: 3001, limit: 2000 });
}
