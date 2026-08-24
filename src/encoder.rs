//! The compressor for one connection, in one direction, and the transaction
//! that decides whether its output reached the wire.
//!
//! RFC 7692 section 7.2.1 defines the producer side as three steps over a
//! *complete* message: deflate it, end it with an empty uncompressed block, then
//! remove that block's four trailing octets. The same section says an endpoint
//! "fragments a compressed message by splitting the result of running this
//! algorithm", so a complete-message encoder is the conforming shape and the
//! host owns framing. The adjacent MUST NOT -- that `00 00 ff ff` is not removed
//! from non-final fragments -- governs the other strategy, where a host calls an
//! encoder once per fragment. Nothing here can enter it.
//!
//! Compression history is the peer's problem as much as ours, so a candidate
//! that may not reach the wire cannot be produced and forgotten. Preparing a
//! message moves the compressor *out* of the encoder and into the returned
//! guard; only committing it or falling back to plain puts it back. Every other
//! outcome -- an error, a dropped guard, a cancelled write, even a leaked guard
//! -- leaves the encoder vacant, and vacant is poisoned.

use flate2::{Compress, FlushCompress, Status};

use crate::codec::TRAILER;
use crate::config::EncoderConfig;
use crate::error::CodecError;
use crate::negotiated::Negotiated;

/// Output room offered to the backend per call.
///
/// A correctness parameter, not a tuning dial -- the decoder trades its scratch
/// against stack, and this trades against nothing. The terminating
/// flush must complete a stored block, and a flush that returns with no room left
/// is re-armed as incomplete, so the next call appends a *second* empty stored
/// block. That output is valid wire and decodes correctly, so no round trip can
/// see it -- only a length or byte comparison can, and at 4 KiB most large
/// level-0 messages carried one.
///
/// Lowering this is therefore not a tuning choice. Raising it does **not** make
/// the output buffer-independent, and must not be read as saying so: zlib sizes
/// each level-0 stored block from the room it is handed, so a message needing
/// more than one round emits one more block header than an unbounded compressor
/// would. There is no fixed value above which that stops -- the first affected
/// size tracks this constant, measured at three ceilings -- and removing it would
/// mean reserving every message in full, taxing the compressible common case to
/// tidy the incompressible one. What is byte-identical at every size measured is
/// levels 1 through 9, plus level 0 below the payload-derived branch, and that is
/// exactly the scope `the_encoder_matches_a_differently_buffered_compressor`
/// asserts.
const BLOCK_ROOM: usize = 1 << 17;

/// The bound the flush half rests on: 65,535 octets of stored data behind a
/// five-octet header must fit with room to spare, or the completing flush is the
/// ambiguous one. Enforced because the failure it prevents is silent.
const _: () = assert!(BLOCK_ROOM > 65_540, "a round must hold one maximal stored block");

/// Slack above a payload's own length, for the room the completing flush needs.
///
/// Not a bound on what DEFLATE adds to a message, which is the reading to avoid:
/// zlib-rs at level 1 expands incompressible input by about 5.5%, so the output
/// routinely exceeds `payload + 64` and level 0 is the *narrowest* case rather
/// than the widest. The room never has to cover the output, because [`drive`]
/// re-reserves every round -- a short room costs rounds, not octets. Only the
/// call that *completes* the flush has to fit, and what it emits is bounded by
/// what the backend still holds, not by the message.
///
/// So this is a measured bound on that residue rather than a derived one, and it
/// is comfortable rather than tight: consumption is flat at 10 octets below one
/// maximal stored block and 15 above it, so the worst case across the whole branch
/// leaves 49 of the 64 unused -- about four times what is needed, on both locked
/// backends. It is nonetheless load-bearing at level 0 alone, because there the
/// flush drains the whole stored message and one octet short appends a redundant
/// block, while at levels 1 through 9 the compressed residue leaves thousands
/// spare and the margin cannot be observed at all.
///
/// `the_encoder_matches_a_differently_buffered_compressor` therefore asserts
/// level 0 byte-exactly across this branch, which is what holds the number:
/// dropping the margin to 8, or halving the request, turns it red with the
/// redundant block's signature. [`BLOCK_ROOM`] and its assertion cover the other
/// branch, where the flush can hold a whole maximal stored block.
const FRAMING_MARGIN: usize = 64;

/// Output room to request per round, for a message of this size.
///
/// [`BLOCK_ROOM`] is a ceiling rather than a fixed request, because it is charged
/// per message and not per connection: a host sending short frames would
/// otherwise ask the allocator for 128 KiB to hold seven octets.
///
/// Neither case is a request to hold the whole output, which is the reading to
/// avoid: [`drive`] re-reserves every round, so a short room costs rounds rather
/// than octets, and at level 1 the output can exceed this request by thousands of
/// octets with no change to a single byte. What has to fit is the call that
/// *completes* the flush.
///
/// Below the ceiling that residue is bounded by the payload, because at level 0
/// the flush drains the whole stored message and [`FRAMING_MARGIN`] covers its
/// framing -- tightly, and measured. At or above the ceiling the residue is
/// bounded instead by one maximal stored block, which is what [`BLOCK_ROOM`]
/// exceeds.
fn room_for(payload_len: usize) -> usize {
    BLOCK_ROOM.min(payload_len.saturating_add(FRAMING_MARGIN))
}

/// The narrowest window `flate2` will build a compressor for.
///
/// `Compress::new_with_window_bits` asserts `9 ..= 15` in flate2's own frontend,
/// before any backend sees the value. RFC 7692 admits 8 on the wire, and both
/// handshake paths refuse to agree to a local 8 rather than clamping it, so this
/// floor is a negotiated precondition here and not a decision.
const MIN_COMPRESSOR_WINDOW_BITS: u8 = 9;

/// The widest window DEFLATE defines.
const MAX_COMPRESSOR_WINDOW_BITS: u8 = 15;

/// RFC 7692 section 7.2.3.6's payload for a message that compresses to nothing:
/// one empty uncompressed DEFLATE block with `BFINAL` unset, `BTYPE` 00, and
/// five padding bits.
const EMPTY_MESSAGE: &[u8] = &[0x00];

/// Everything the compressor is built from.
///
/// Unlike the inflater's, this is not kept: `Compress::reset` takes no argument
/// and preserves both level and window on each locked backend, so there is no
/// route that has to rebuild from what it stored. It exists to name the mapping
/// from an agreement to flate2's arguments in one place.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CompressorConfig {
    level: u32,
    window_bits: u8,
}

impl CompressorConfig {
    /// The local direction of an agreement. Never the peer accessors: the peer's
    /// window and takeover setting describe the inflater, and a swap here would
    /// compress to a width this side never agreed to hold.
    fn for_local(negotiated: &Negotiated, config: EncoderConfig) -> Self {
        Self { level: config.level(), window_bits: negotiated.local_max_window_bits() }
    }

    /// The only place this crate constructs a compressor.
    fn build(self) -> Compress {
        // flate2 panics below 9. Both handshake paths reject a local 8 where it
        // is configured -- `ClientWindowTooNarrow` and a declined offer -- so
        // this states the invariant at the boundary that depends on it rather
        // than letting a future route reach flate2's assert instead.
        // `every_agreement_builds_a_compressor_in_range` exhausts both paths.
        #[expect(
            clippy::panic,
            clippy::manual_assert,
            reason = "a negotiated local width below 9 is a crate defect, pinned by `every_agreement_builds_a_compressor_in_range`; \
                      written as a panic so `panic = \"deny\"` keeps accounting for the site, which it would not for an `assert!`"
        )]
        if !(MIN_COMPRESSOR_WINDOW_BITS..=MAX_COMPRESSOR_WINDOW_BITS).contains(&self.window_bits) {
            panic!("negotiation admitted a local window of {} bits", self.window_bits);
        }
        Compress::new_with_window_bits(
            flate2::Compression::new(self.level),
            // PMD carries raw DEFLATE. A zlib header would be two octets the
            // peer's inflater reads as compressed data.
            false,
            self.window_bits,
        )
    }
}

/// The compressor for one connection, in one direction.
///
/// Holds this side's compression history between messages, and holds it only
/// while no candidate is outstanding. A vacant encoder is a poisoned one: see
/// [`Encoder::prepare_message`].
#[derive(Debug)]
pub struct Encoder {
    /// `None` means a candidate is outstanding, or one was never resolved. The
    /// distinction does not matter to a caller, because the borrow makes the
    /// first case unobservable and the second is terminal.
    compressor: Option<Compress>,
    reset_between_messages: bool,
}

impl Encoder {
    pub(crate) fn for_agreement(negotiated: &Negotiated, config: EncoderConfig) -> Self {
        Self {
            compressor: Some(CompressorConfig::for_local(negotiated, config).build()),
            reset_between_messages: negotiated.local_no_context_takeover(),
        }
    }

    /// Compress one complete message, without deciding that it will be sent.
    ///
    /// The returned guard holds both the candidate bytes and the compressor that
    /// produced them. Until it resolves, this encoder has no compressor, so the
    /// history that candidate advanced cannot be built on and cannot be
    /// abandoned by accident:
    ///
    /// * [`commit`](PreparedMessage::commit) says the bytes will reach the peer,
    ///   and returns the advanced history.
    /// * [`reset_to_plain`](PreparedMessage::reset_to_plain) says they will not,
    ///   and returns an empty one.
    /// * Anything else -- a dropped guard, an unknown partial write, a
    ///   `mem::forget` -- leaves the encoder vacant, and every later call
    ///   returns [`CodecError::Poisoned`] before a backend is touched.
    ///
    /// That last case is the point. A host whose write was cancelled after an
    /// unknown number of octets cannot know what the peer received, and resuming
    /// from history the peer may not hold decodes every later message to
    /// nonsense. Failing the connection is the only answer that does not depend
    /// on knowing.
    pub fn prepare_message(&mut self, payload: &[u8]) -> Result<PreparedMessage<'_>, CodecError> {
        let mut compressor = self.compressor.take().ok_or(CodecError::Poisoned)?;
        // On the error path `compressor` is dropped here, which is what makes a
        // prepare failure terminal without a flag to keep in step.
        let bytes = produce(&mut compressor, payload)?;
        Ok(PreparedMessage { encoder: self, compressor, bytes })
    }
}

/// A compressed message that has not yet been declared sent or discarded.
///
/// Deliberately has no `Drop` impl. Dropping it must poison the encoder, and the
/// way to guarantee that without depending on `Drop` running is for the
/// compressor to live *in* here: safe `std::mem::forget` leaks the guard, which
/// leaks the compressor, and the encoder stays vacant either way.
#[must_use = "an unresolved prepared message poisons the encoder"]
#[derive(Debug)]
pub struct PreparedMessage<'a> {
    encoder: &'a mut Encoder,
    compressor: Compress,
    bytes: Vec<u8>,
}

impl PreparedMessage<'_> {
    /// The candidate payload: RFC 7692 section 7.2.1 applied to the whole
    /// message, with the four-octet trailer already removed.
    ///
    /// A host may frame these bytes in any legal fragment sequence, setting RSV1
    /// on the first frame only.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The candidate payload, mutably, for a reversible transport transform such
    /// as client masking.
    ///
    /// Not a general post-compression seam: anything that changes what the peer
    /// inflates changes what this side's history claims it sent.
    #[must_use]
    pub fn as_bytes_mut(&mut self) -> &mut [u8] {
        &mut self.bytes
    }

    /// Declare that these bytes will appear on the wire, and take them.
    ///
    /// A host that queues rather than writes calls this only once insertion can
    /// no longer fail; a host that writes directly reads
    /// [`as_bytes`](Self::as_bytes), writes all of it, then commits.
    #[must_use]
    pub fn commit(self) -> Vec<u8> {
        let Self { encoder, mut compressor, bytes } = self;
        if encoder.reset_between_messages {
            reset(&mut compressor);
        }
        encoder.compressor = Some(compressor);
        bytes
    }

    /// Declare that none of these bytes will appear on the wire.
    ///
    /// The history the candidate advanced is dropped, so the next compressed
    /// message starts from an empty window. That may cost compression the peer
    /// would have honoured, and it is the only wire-safe answer: the peer's
    /// retained history is then a superset of ours, and a stream that never
    /// references it cannot be decoded wrongly by holding it.
    ///
    /// The host still has its original payload and sends it with RSV1 clear.
    pub fn reset_to_plain(self) {
        let Self { encoder, mut compressor, .. } = self;
        reset(&mut compressor);
        encoder.compressor = Some(compressor);
    }
}

/// Start this side's compression history over.
///
/// `Compress::reset` is the whole operation at every negotiated width, which is
/// what makes this the encoder's only reinitialisation route. It takes no
/// arguments and both locked backends keep the level and the window across it --
/// the C route calls `deflateReset`, which zlib documents as preserving the
/// compression level and other attributes, and zlib-rs reinitialises the LZ
/// state while retaining the stream configuration. The inflater's
/// rebuild-below-15 branch exists because `Decompress::reset` *does* discard a
/// narrower window; copying it here would allocate to preserve nothing.
fn reset(compressor: &mut Compress) {
    compressor.reset();
}

/// RFC 7692 section 7.2.1 steps 1 through 3, for one complete message.
fn produce(compressor: &mut Compress, payload: &[u8]) -> Result<Vec<u8>, CodecError> {
    let room = room_for(payload.len());
    let mut output = Vec::new();
    feed(compressor, payload, &mut output, room)?;
    sync_flush(compressor, &mut output, room)?;
    let mut message = strip_or_synthesize(payload, output)?;
    // A round reserves room for what the message could produce and a short one
    // needs almost none of it, so the returned vector would otherwise carry that
    // slack until the host drops it. What the allocator does with the request is
    // its own business -- `Vec::shrink_to_fit` may shrink in place or reallocate,
    // and either way may leave excess capacity -- so this asks for the space back
    // without claiming it comes back.
    message.shrink_to_fit();
    Ok(message)
}

/// Step 1: the whole payload into raw DEFLATE, holding nothing back.
fn feed(
    compressor: &mut Compress,
    payload: &[u8],
    output: &mut Vec<u8>,
    room: usize,
) -> Result<(), CodecError> {
    let mut input = payload;
    while !input.is_empty() {
        let round = drive(compressor, input, output, FlushCompress::None, room)?;
        // Keyed on what moved, not on the status: `Ok` is a conforming answer
        // for a call with nowhere left to put output, so reading termination off
        // the status would drop a tail in silence.
        if round.consumed == 0 && round.produced == 0 {
            return Err(CodecError::Stalled);
        }
        input = input.get(round.consumed..).ok_or(CodecError::CompressionFailed)?;
    }
    Ok(())
}

/// Step 2: end the message with an empty uncompressed block.
///
/// `Z_SYNC_FLUSH` completes the current block, pads to a byte boundary, and
/// appends that empty block -- which is what leaves `00 00 ff ff` for step 3 to
/// take. RFC 7692 section 7.3 names it as the ordinary mechanism, and `Finish`
/// is never used: it would end the DEFLATE stream and forfeit the history the
/// next message may reference.
///
/// The loop repeats the flush while a call returns with no output room left,
/// because that is zlib's documented protocol for a flush that did not fit. It
/// is not a free repetition: zlib cannot signal "complete" apart from "the
/// buffer filled exactly", so it sets `last_flush = -1` on a full return and a
/// repeat becomes a *new* sync flush, which on an already-drained stream appends
/// a second empty stored block. [`BLOCK_ROOM`] is what keeps the first call from
/// ever being the ambiguous one; the loop remains for a backend holding more
/// pending output than that, which would get the redundant block -- valid wire,
/// never a wrong stream.
fn sync_flush(
    compressor: &mut Compress,
    output: &mut Vec<u8>,
    room: usize,
) -> Result<(), CodecError> {
    loop {
        let round = drive(compressor, &[], output, FlushCompress::Sync, room)?;
        if round.produced < round.room {
            return Ok(());
        }
    }
}

/// Step 3: remove the four octets the peer's decoder is required to feed back.
///
/// Exactly the tail, never a backward scan: `00 00 ff ff` occurs inside ordinary
/// compressed data, and section 7.2.3.5 shows a conforming message where it
/// appears mid-payload between two DEFLATE blocks.
///
/// A message that produced no bytes at all is the one case where the tail is
/// legitimately absent. Both locked backends refuse a redundant flush -- zlib
/// returns `Z_BUF_ERROR` when there is no input and the requested flush does not
/// outrank the last one -- so an empty message that directly follows another
/// message under context takeover yields nothing to strip. Section 7.2.3.6
/// answers exactly this: "If the compression library being used doesn't generate
/// any data when its buffer is empty, an empty uncompressed DEFLATE block can be
/// built and used for this purpose". That block is [`EMPTY_MESSAGE`], and it is
/// byte-identical to what a fresh compressor emits for the same message.
///
/// The condition is the backend's observable output and not
/// `local_no_context_takeover`, so the arm stays correct on a backend that
/// declines a fresh empty flush too. No bytes for a payload that *had* bytes is
/// a fault either way.
fn strip_or_synthesize(payload: &[u8], mut output: Vec<u8>) -> Result<Vec<u8>, CodecError> {
    if output.ends_with(TRAILER) {
        output.truncate(output.len().saturating_sub(TRAILER.len()));
        Ok(output)
    } else if payload.is_empty() && output.is_empty() {
        Ok(EMPTY_MESSAGE.to_vec())
    } else {
        Err(CodecError::CompressionFailed)
    }
}

/// What one backend call moved, and the room it actually had.
///
/// `room` is read back rather than assumed: `Vec::reserve` may hand out more
/// than it was asked for, and comparing a flush's output against the *request*
/// would repeat a flush that completed with room to spare.
struct Round {
    consumed: usize,
    produced: u64,
    room: u64,
}

/// Drive the compressor once, into the output vector's spare capacity.
///
/// `StreamEnd` is a fault rather than termination: nothing here asks for
/// `Finish`, so a backend reporting a finished stream has ended one this side
/// still owes messages on.
fn drive(
    compressor: &mut Compress,
    input: &[u8],
    output: &mut Vec<u8>,
    flush: FlushCompress,
    room: usize,
) -> Result<Round, CodecError> {
    output.reserve(room);
    let room = u64::try_from(output.capacity().saturating_sub(output.len()))
        .map_err(|_| CodecError::CompressionFailed)?;
    let before = (compressor.total_in(), compressor.total_out());
    let status =
        compressor.compress_vec(input, output, flush).map_err(|_| CodecError::CompressionFailed)?;
    if status == Status::StreamEnd {
        return Err(CodecError::CompressionFailed);
    }
    let consumed = usize::try_from(compressor.total_in().saturating_sub(before.0))
        .map_err(|_| CodecError::CompressionFailed)?;
    Ok(Round { consumed, produced: compressor.total_out().saturating_sub(before.1), room })
}

#[cfg(test)]
#[expect(clippy::expect_used, clippy::panic, reason = "a panic is how a test reports")]
mod tests {
    use super::{
        strip_or_synthesize, CodecError, CompressorConfig, EMPTY_MESSAGE,
        MAX_COMPRESSOR_WINDOW_BITS, MIN_COMPRESSOR_WINDOW_BITS, TRAILER,
    };
    use crate::config::{ClientConfig, EncoderConfig, ServerConfig};
    use crate::negotiated::{Negotiated, PmdComposition, Role};
    use crate::{ClientOffer, ServerHandshake};
    use http::{header::SEC_WEBSOCKET_EXTENSIONS, HeaderMap, HeaderValue};

    /// RFC 7692 section 7.2.3.6's octet is the one this crate synthesizes.
    #[test]
    fn the_synthesized_empty_message_is_the_rfc_octet() {
        assert_eq!(EMPTY_MESSAGE, &[0x00]);
    }

    /// Empty output for a payload that had bytes stays fatal, and only a unit
    /// test can say so.
    ///
    /// No public input reaches that state: neither locked backend returns no
    /// bytes for a non-empty payload, so an integration row cannot construct it
    /// and cannot kill a mutant that widens the synthesis condition to the
    /// output alone. Calling the step directly can.
    #[test]
    fn empty_output_for_a_non_empty_payload_is_not_synthesized() {
        assert_eq!(
            strip_or_synthesize(b"not empty", Vec::new()),
            Err(CodecError::CompressionFailed),
            "a payload with bytes must never take the empty-message branch"
        );
        assert_eq!(strip_or_synthesize(b"", Vec::new()), Ok(EMPTY_MESSAGE.to_vec()));

        // The control that this row is not simply asserting that everything
        // fails: a present trailer is stripped, exactly four octets.
        let mut with_trailer = vec![0xf2, 0x48];
        with_trailer.extend_from_slice(TRAILER);
        assert_eq!(strip_or_synthesize(b"Hello", with_trailer), Ok(vec![0xf2, 0x48]));
    }

    /// The local direction of the agreement, for every width both roles can
    /// negotiate, read off a real agreement rather than a helper beside one.
    ///
    /// Both roles, because `local_max_window_bits` reads the opposite stored
    /// field in each: with one role the two fields would only have to agree.
    /// The peer field is deliberately set to a different value so a swap shows.
    ///
    /// This is a mapping seam and not a claim about the arguments `flate2`
    /// receives -- `Compress` exposes no read-back, so a literal substituted
    /// inside `build` still passes this row. What guards those substitutions is
    /// behavioural and lives in `tests/encoder.rs`: unlike the inflater's, the
    /// compressor's declared window is observable in the output size on *both*
    /// backends, so `the_local_window_bounds_back_references` kills them there.
    #[test]
    fn the_compressor_maps_the_local_direction_for_both_roles() {
        for local in MIN_COMPRESSOR_WINDOW_BITS..=MAX_COMPRESSOR_WINDOW_BITS {
            let peer = MAX_COMPRESSOR_WINDOW_BITS - (local - MIN_COMPRESSOR_WINDOW_BITS);
            let expected =
                CompressorConfig { level: EncoderConfig::new().level(), window_bits: local };

            // Role::Client reads client_max_window_bits as local.
            let client = Negotiated::new(Role::Client, false, false, peer, local);
            assert_eq!(
                CompressorConfig::for_local(&client, EncoderConfig::new()),
                expected,
                "client, local {local}"
            );

            let server = Negotiated::new(Role::Server, false, false, local, peer);
            assert_eq!(
                CompressorConfig::for_local(&server, EncoderConfig::new()),
                expected,
                "server, local {local}"
            );
        }
    }

    /// The takeover flag the encoder resets on, read off the real `Encoder` both
    /// roles build, with the peer's value set opposite so a swap shows.
    #[test]
    fn the_encoder_resets_on_the_local_takeover_flag_for_both_roles() {
        for local in [false, true] {
            let client = Negotiated::new(Role::Client, !local, local, 15, 15);
            let (encoder, _) = client.into_codecs(EncoderConfig::new());
            assert_eq!(encoder.reset_between_messages, local, "client, local {local}");

            let server = Negotiated::new(Role::Server, local, !local, 15, 15);
            let (encoder, _) = server.into_codecs(EncoderConfig::new());
            assert_eq!(encoder.reset_between_messages, local, "server, local {local}");
        }
    }

    /// Every agreement the two handshake paths can mint builds a compressor in
    /// flate2's range, so the panic in `build` is unreachable from public input.
    ///
    /// Exhausts the wire's whole width space, 8 through 15, on both sides of
    /// both roles -- 8 included, because that is the value flate2 would panic on
    /// and the one both paths are supposed to refuse.
    #[test]
    fn every_agreement_builds_a_compressor_in_range() {
        let mut minted = 0usize;
        let mut refused = 0usize;
        for local in 8..=15u8 {
            for peer in 8..=15u8 {
                for takeover in [false, true] {
                    for agreement in client_agreements(local, peer, takeover)
                        .into_iter()
                        .chain(server_agreements(local, peer, takeover))
                    {
                        match agreement {
                            Ok(negotiated) => {
                                let bits = negotiated.local_max_window_bits();
                                assert!(
                                    (MIN_COMPRESSOR_WINDOW_BITS..=MAX_COMPRESSOR_WINDOW_BITS)
                                        .contains(&bits),
                                    "an agreement minted local {bits} from local {local}, peer {peer}"
                                );
                                // Not just the accessor: the real constructor.
                                let _ = negotiated.into_codecs(EncoderConfig::new());
                                minted += 1;
                            }
                            Err(()) => refused += 1,
                        }
                    }
                }
            }
        }
        assert!(minted > 0, "the sweep minted no agreements, so it asserted nothing");
        assert!(
            refused > 0,
            "no width was refused, so the sweep never exercised the 8 both paths reject"
        );
    }

    /// Client agreements for a local (client) and peer (server) width, one per
    /// response shape a server could legally send for that pair.
    fn client_agreements(local: u8, peer: u8, takeover: bool) -> Vec<Result<Negotiated, ()>> {
        let Ok(config) = ClientConfig::new()
            .client_no_context_takeover(takeover)
            .client_max_window_bits(local)
            .and_then(|c| c.server_max_window_bits(peer))
        else {
            // A local 8 is refused where it is configured, which is the point.
            return vec![Err(())];
        };
        let mut request = HeaderMap::new();
        let offer = ClientOffer::install(config, &mut request).expect("fresh map");
        let sealed = offer.seal(&request).expect("the offer is unchanged");
        let response = format!(
            "permessage-deflate{}; server_max_window_bits={peer}; client_max_window_bits={local}",
            if takeover { "; client_no_context_takeover" } else { "" }
        );
        let mut headers = HeaderMap::new();
        headers.append(
            SEC_WEBSOCKET_EXTENSIONS,
            HeaderValue::from_str(&response).expect("a valid header value"),
        );
        vec![sealed
            .finish(&headers, PmdComposition::Compatible)
            .map_or(Err(()), |selected| selected.ok_or(()).map_err(|()| unreachable_decline()))]
    }

    /// Server agreements for a local (server) and peer (client) width.
    fn server_agreements(local: u8, peer: u8, takeover: bool) -> Vec<Result<Negotiated, ()>> {
        let Ok(config) = ServerConfig::new()
            .server_no_context_takeover(takeover)
            .server_max_window_bits(local)
            .and_then(|c| c.client_max_window_bits(peer))
        else {
            return vec![Err(())];
        };
        let mut request = HeaderMap::new();
        request.append(
            SEC_WEBSOCKET_EXTENSIONS,
            HeaderValue::from_static("permessage-deflate; client_max_window_bits"),
        );
        let Ok(Some(handshake)) = ServerHandshake::accept(config, &request) else {
            return vec![Err(())];
        };
        let mut response = HeaderMap::new();
        response.append(SEC_WEBSOCKET_EXTENSIONS, handshake.value().clone());
        vec![handshake
            .finish(&response, PmdComposition::Compatible)
            .map_or(Err(()), |selected| selected.ok_or(()))]
    }

    /// A server that echoed its own proposal cannot decline it, so this arm
    /// reports a crate defect rather than a case the sweep should tolerate.
    fn unreachable_decline() -> ! {
        panic!("a response carrying the crate's own selection declined it");
    }

    /// A level outside zlib's domain is refused before any codec exists, and the
    /// backend's own default -- which `EncoderConfig::new` reads rather than
    /// restates -- is inside the range that refusal enforces.
    #[test]
    fn a_level_outside_the_domain_is_refused_at_configuration() {
        for level in [10u32, 11, 255, u32::MAX] {
            assert!(EncoderConfig::new().compression_level(level).is_err(), "level {level}");
        }
        for level in 0..=9u32 {
            let config =
                EncoderConfig::new().compression_level(level).expect("zlib's whole domain");
            assert_eq!(config.level(), level);
        }
        // `u32` has no values below the floor, so only the ceiling can be
        // crossed; the type carries the other half of the range check.
        let default = EncoderConfig::new().level();
        assert!(
            EncoderConfig::new().compression_level(default).is_ok(),
            "the backend's default level {default} is outside the domain this crate accepts"
        );
    }
}
