//! The compressor for one connection, in one direction, and the two
//! transactions that decide whether its output reached the wire.
//!
//! RFC 7692 section 7.2.1 defines the producer side as three steps over a
//! *complete* message: deflate it, end it with an empty uncompressed block, then
//! remove that block's four trailing octets. The same section permits two ways
//! to build fragments from that, and this module implements both.
//!
//! [`Encoder::prepare_message`] is the first: an endpoint "fragments a
//! compressed message by splitting the result of running this algorithm", so it
//! takes a whole message, runs all three steps once, and the host splits what
//! comes back. [`Encoder::begin_streaming_message`] is the second: "even when
//! only part of the payload is available, a fragment can be built by compressing
//! the available data" and byte-aligning its end. There steps 1 and 2 run per
//! fragment and step 3 runs only on the last, which is what the adjacent MUST
//! NOT requires -- `00 00 ff ff` stays on every non-final fragment.
//!
//! Compression history is the peer's problem as much as ours, so a candidate
//! that may not reach the wire cannot be produced and forgotten. Preparing
//! anything moves the compressor *out* of the encoder and into the returned
//! state; only resolving that state puts it back. Every other outcome -- an
//! error, a dropped guard, a cancelled write, even a leaked guard -- leaves the
//! encoder vacant, and vacant is poisoned.
//!
//! What the two do not share is an exit. A whole-message candidate can still be
//! abandoned: [`PreparedMessage::reset_to_plain`] throws away the history it
//! advanced and the host sends its payload with RSV1 clear. A stream has no such
//! answer once its first fragment commits, because by then those octets are on
//! the wire and the peer has inflated them. So streaming offers no fallback at
//! all, rather than one that silently stops being available part-way through a
//! message.

use flate2::{Compress, FlushCompress, Status};

use crate::codec::TRAILER;
use crate::config::EncoderConfig;
use crate::error::CodecError;
use crate::negotiated::Negotiated;

/// Output room offered to the backend per call.
///
/// A correctness parameter first, which is what separates it from the decoder's
/// scratch: below a bound this is wrong, not merely slower. It still trades --
/// allocator requests, backend rounds, and above the payload-derived branch which
/// level-0 block partitioning the backend is permitted to choose -- so a
/// conforming value is not a cost-free or byte-identical one. The terminating
/// flush must complete a stored block, and a flush that returns with no room left
/// is re-armed as incomplete, so the next call appends a *second* empty stored
/// block. That output is valid wire and decodes correctly, so no round trip can
/// see it -- only a length or byte comparison can, and at 4 KiB most large
/// level-0 payload chunks carried one.
///
/// The ceiling branch is charged per *produced chunk* and not per WebSocket
/// message, which is what lets one constant serve both producers: a call that
/// completes a flush has to fit one maximal stored block and its header with
/// room left, and that bound is the same whether the chunk is a whole message or
/// one fragment of a streamed one. A previous *intermediate* round may still
/// leave pending output behind, and [`sync_flush`] already repeats for that.
///
/// Lowering this is therefore not a tuning choice. Raising it does **not** make
/// the output buffer-independent, and must not be read as saying so: zlib sizes
/// each level-0 stored block from the room it is handed, so a chunk needing
/// more than one round emits one more block header than an unbounded compressor
/// would. There is no fixed value above which that stops -- the first affected
/// size tracks this constant, measured at three ceilings -- and removing it would
/// mean reserving every chunk in full, taxing the compressible common case to
/// tidy the incompressible one. What is byte-identical at every size measured is
/// levels 1 through 9, plus level 0 below the payload-derived branch, and that is
/// exactly the scope `the_encoder_matches_a_differently_buffered_compressor`
/// asserts.
const BLOCK_ROOM: usize = 1 << 17;

/// The bound the flush half rests on: 65,535 octets of stored data behind a
/// five-octet header must fit with room to spare, or the completing flush is the
/// ambiguous one. Enforced because the failure it prevents is silent.
const _: () = assert!(BLOCK_ROOM > 65_540, "a round must hold one maximal stored block");

/// Slack above a payload chunk's own length, for the room the completing flush
/// needs.
///
/// Not a bound on what DEFLATE adds to a chunk, which is the reading to avoid:
/// zlib-rs at level 1 expands incompressible input by about 5.5%, so the output
/// routinely exceeds `payload + 64` and level 0 is the *narrowest* case rather
/// than the widest. The room never has to cover the output, because [`drive`]
/// re-reserves every round -- a short room costs rounds, not octets. Only the
/// call that *completes* the flush has to fit, and what it emits is bounded by
/// what the backend still holds, not by the message.
///
/// That residue is per chunk rather than per message, which is why streaming
/// needs no second number: each fragment ends in a sync flush that drains the
/// compressor, so whatever the next call has to frame was produced by the next
/// chunk alone.
///
/// So this is a measured bound on that residue rather than a derived one, and it
/// is comfortable rather than tight: consumption is `5 x blocks + 5`, and at most
/// two blocks fit below the branch edge, so it is ten or fifteen octets and the
/// worst case leaves 49 of the 64 unused -- bounded by arithmetic, not by the
/// sizes that happened to be sampled, and identical on both locked backends. It
/// is nonetheless load-bearing at level 0 alone, because there the flush drains
/// the whole stored chunk and one octet short appends a redundant block, while
/// at levels 1 through 9 the compressed residue leaves thousands spare and the
/// margin cannot be observed at all.
///
/// `the_encoder_matches_a_differently_buffered_compressor` therefore asserts
/// level 0 byte-exactly across this branch, which is what holds the number:
/// dropping the margin to 8, or halving the request, turns it red with the
/// redundant block's signature. [`BLOCK_ROOM`] and its assertion cover the other
/// branch, where the flush can hold a whole maximal stored block.
const FRAMING_MARGIN: usize = 64;

/// Output room to request per round, for a message of this size.
///
/// Called with each chunk's own length: a whole message for
/// [`Encoder::prepare_message`], one fragment's payload for each streaming
/// prepare.
///
/// [`BLOCK_ROOM`] is a ceiling rather than a fixed request, because it is charged
/// per produced fragment or complete message and not per connection: a host
/// sending short frames would otherwise ask the allocator for 128 KiB to hold
/// seven octets.
///
/// Neither case is a request to hold the whole output, which is the reading to
/// avoid: [`drive`] re-reserves every round, so a short room costs rounds rather
/// than octets, and at level 1 the output can exceed this request by thousands of
/// octets with no change to a single byte. What has to fit is the call that
/// *completes* the flush.
///
/// Below the ceiling that residue is bounded by the payload, because at level 0
/// the flush drains the whole stored chunk, and [`FRAMING_MARGIN`] covers its
/// framing with room to spare: two maximal stored blocks reach 131,070, so at most
/// two block headers fit below the branch edge and consumption is `5 x blocks + 5`
/// -- ten or fifteen octets, by arithmetic rather than by sampling. At or above the
/// ceiling the residue is bounded instead by one maximal stored block, which is
/// what [`BLOCK_ROOM`] exceeds.
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

    /// Begin a message whose payload the host does not have in full.
    ///
    /// The other producer RFC 7692 section 7.2.1 permits: each fragment is
    /// compressed from the bytes available when the host asks, instead of one
    /// compressed message being sliced afterwards. Use it when the source is a
    /// stream and holding the whole message to compress it is what you are
    /// trying to avoid; use [`prepare_message`](Self::prepare_message) whenever
    /// the message is already in memory, because a flush per fragment costs
    /// ratio.
    ///
    /// This takes the compressor and makes no backend call, so beginning a
    /// stream is not itself compression -- but it *is* already the point of no
    /// return for the encoder, exactly as preparing a whole message is. The
    /// returned state must reach
    /// [`prepare_final_fragment`](StreamingMessage::prepare_final_fragment) and
    /// commit, or this direction is poisoned.
    ///
    /// Everything on the wire stays the host's: which bytes go in a fragment,
    /// the continuation opcodes, FIN, RSV1 on the first data frame only, and
    /// masking.
    ///
    /// ```
    /// # use http::{header::SEC_WEBSOCKET_EXTENSIONS, HeaderMap, HeaderValue};
    /// # use ws_pmd::{ClientConfig, ClientOffer, EncoderConfig, PmdComposition};
    /// # let mut request = HeaderMap::new();
    /// # let offer = ClientOffer::install(ClientConfig::new(), &mut request)
    /// #     .expect("a fresh map");
    /// # let mut response = HeaderMap::new();
    /// # response.append(
    /// #     SEC_WEBSOCKET_EXTENSIONS,
    /// #     HeaderValue::from_static("permessage-deflate"),
    /// # );
    /// # let agreed = offer
    /// #     .seal(&request)
    /// #     .expect("the offer is unchanged")
    /// #     .finish(&response, PmdComposition::Compatible)
    /// #     .expect("the response is legal")
    /// #     .expect("the server selected it");
    /// # let (mut encoder, _decoder) = agreed.into_codecs(EncoderConfig::new());
    /// # let mut wire: Vec<Vec<u8>> = Vec::new();
    /// let mut stream = encoder.begin_streaming_message()?;
    ///
    /// // One continuation frame per chunk. RSV1 on the first, FIN on none.
    /// for chunk in [&b"the first half "[..], &b"and the second"[..]] {
    ///     let fragment = stream.prepare_non_final_fragment(chunk)?;
    ///     wire.push(fragment.as_bytes().to_vec()); // write it, then commit
    ///     let (_bytes, next) = fragment.commit();
    ///     stream = next;
    /// }
    ///
    /// // The last frame carries FIN, and only here is the trailer removed.
    /// let last = stream.prepare_final_fragment(b"!")?;
    /// wire.push(last.as_bytes().to_vec());
    /// let _bytes = last.commit();
    /// # Ok::<(), ws_pmd::CodecError>(())
    /// ```
    pub fn begin_streaming_message(&mut self) -> Result<StreamingMessage<'_>, CodecError> {
        let compressor = self.compressor.take().ok_or(CodecError::Poisoned)?;
        Ok(StreamingMessage { encoder: self, compressor })
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

/// A message being compressed a fragment at a time, between fragments.
///
/// Holds the compressor while it is neither in the encoder nor in a prepared
/// fragment, so the encoder is vacant for as long as this exists. There is
/// exactly one of these per message and it is consumed by preparing a fragment:
/// fragment N+1 cannot be started until N resolves, because preparing N took the
/// only value that can start another.
///
/// Dropping or forgetting it is the terminal outcome, and there is no
/// `reset_to_plain` counterpart. Once any fragment has committed, its octets are
/// on the wire and the peer has inflated them, so this side cannot decide the
/// message will be sent uncompressed instead; offering that exit only before the
/// first commit would be an escape hatch that stops working part-way through a
/// message, which is worse than not having one.
/// # Linearity, and what it refuses
///
/// Preparing a fragment consumes this, so there is no live parent while one is
/// unresolved and fragment N+1 cannot be started before N commits:
///
/// ```compile_fail,E0382
/// # use http::{header::SEC_WEBSOCKET_EXTENSIONS, HeaderMap, HeaderValue};
/// # use ws_pmd::{ClientConfig, ClientOffer, EncoderConfig, PmdComposition};
/// # let mut request = HeaderMap::new();
/// # let offer = ClientOffer::install(ClientConfig::new(), &mut request)
/// #     .expect("a fresh map");
/// # let mut response = HeaderMap::new();
/// # response.append(
/// #     SEC_WEBSOCKET_EXTENSIONS,
/// #     HeaderValue::from_static("permessage-deflate"),
/// # );
/// # let (mut encoder, _decoder) = offer
/// #     .seal(&request)
/// #     .expect("the offer is unchanged")
/// #     .finish(&response, PmdComposition::Compatible)
/// #     .expect("the response is legal")
/// #     .expect("the server selected it")
/// #     .into_codecs(EncoderConfig::new());
/// let open = encoder.begin_streaming_message()?;
/// let pending = open.prepare_non_final_fragment(b"first")?;
/// let second = open.prepare_non_final_fragment(b"second")?;
/// # let _ = (pending, second);
/// # Ok::<(), ws_pmd::CodecError>(())
/// ```
///
/// The same setup, one line apart, with the commit that makes it legal:
///
/// ```
/// # use http::{header::SEC_WEBSOCKET_EXTENSIONS, HeaderMap, HeaderValue};
/// # use ws_pmd::{ClientConfig, ClientOffer, EncoderConfig, PmdComposition};
/// # let mut request = HeaderMap::new();
/// # let offer = ClientOffer::install(ClientConfig::new(), &mut request)
/// #     .expect("a fresh map");
/// # let mut response = HeaderMap::new();
/// # response.append(
/// #     SEC_WEBSOCKET_EXTENSIONS,
/// #     HeaderValue::from_static("permessage-deflate"),
/// # );
/// # let (mut encoder, _decoder) = offer
/// #     .seal(&request)
/// #     .expect("the offer is unchanged")
/// #     .finish(&response, PmdComposition::Compatible)
/// #     .expect("the response is legal")
/// #     .expect("the server selected it")
/// #     .into_codecs(EncoderConfig::new());
/// let open = encoder.begin_streaming_message()?;
/// let pending = open.prepare_non_final_fragment(b"first")?;
/// let (_bytes, open) = pending.commit();
/// let second = open.prepare_non_final_fragment(b"second")?;
/// # let _ = second;
/// # Ok::<(), ws_pmd::CodecError>(())
/// ```
///
/// Continuing after FIN is not rejected at runtime -- the final commit returns
/// bytes and nothing else, so there is no state to continue from:
///
/// ```compile_fail,E0599
/// # use http::{header::SEC_WEBSOCKET_EXTENSIONS, HeaderMap, HeaderValue};
/// # use ws_pmd::{ClientConfig, ClientOffer, EncoderConfig, PmdComposition};
/// # let mut request = HeaderMap::new();
/// # let offer = ClientOffer::install(ClientConfig::new(), &mut request)
/// #     .expect("a fresh map");
/// # let mut response = HeaderMap::new();
/// # response.append(
/// #     SEC_WEBSOCKET_EXTENSIONS,
/// #     HeaderValue::from_static("permessage-deflate"),
/// # );
/// # let (mut encoder, _decoder) = offer
/// #     .seal(&request)
/// #     .expect("the offer is unchanged")
/// #     .finish(&response, PmdComposition::Compatible)
/// #     .expect("the response is legal")
/// #     .expect("the server selected it")
/// #     .into_codecs(EncoderConfig::new());
/// let open = encoder.begin_streaming_message()?;
/// let last = open.prepare_final_fragment(b"the end")?;
/// let more = last.commit().prepare_non_final_fragment(b"after FIN")?;
/// # let _ = more;
/// # Ok::<(), ws_pmd::CodecError>(())
/// ```
///
/// Starting a *new* message is how a host goes on, and it compiles:
///
/// ```
/// # use http::{header::SEC_WEBSOCKET_EXTENSIONS, HeaderMap, HeaderValue};
/// # use ws_pmd::{ClientConfig, ClientOffer, EncoderConfig, PmdComposition};
/// # let mut request = HeaderMap::new();
/// # let offer = ClientOffer::install(ClientConfig::new(), &mut request)
/// #     .expect("a fresh map");
/// # let mut response = HeaderMap::new();
/// # response.append(
/// #     SEC_WEBSOCKET_EXTENSIONS,
/// #     HeaderValue::from_static("permessage-deflate"),
/// # );
/// # let (mut encoder, _decoder) = offer
/// #     .seal(&request)
/// #     .expect("the offer is unchanged")
/// #     .finish(&response, PmdComposition::Compatible)
/// #     .expect("the response is legal")
/// #     .expect("the server selected it")
/// #     .into_codecs(EncoderConfig::new());
/// let open = encoder.begin_streaming_message()?;
/// let last = open.prepare_final_fragment(b"the end")?;
/// let _bytes = last.commit();
/// let more = encoder.begin_streaming_message()?.prepare_non_final_fragment(b"a new message")?;
/// # let _ = more;
/// # Ok::<(), ws_pmd::CodecError>(())
/// ```
///
/// And a consumed state cannot be read again afterwards:
///
/// ```compile_fail,E0382
/// # use http::{header::SEC_WEBSOCKET_EXTENSIONS, HeaderMap, HeaderValue};
/// # use ws_pmd::{ClientConfig, ClientOffer, EncoderConfig, PmdComposition};
/// # let mut request = HeaderMap::new();
/// # let offer = ClientOffer::install(ClientConfig::new(), &mut request)
/// #     .expect("a fresh map");
/// # let mut response = HeaderMap::new();
/// # response.append(
/// #     SEC_WEBSOCKET_EXTENSIONS,
/// #     HeaderValue::from_static("permessage-deflate"),
/// # );
/// # let (mut encoder, _decoder) = offer
/// #     .seal(&request)
/// #     .expect("the offer is unchanged")
/// #     .finish(&response, PmdComposition::Compatible)
/// #     .expect("the response is legal")
/// #     .expect("the server selected it")
/// #     .into_codecs(EncoderConfig::new());
/// let open = encoder.begin_streaming_message()?;
/// let pending = open.prepare_non_final_fragment(b"first")?;
/// let (_bytes, open) = pending.commit();
/// let spare = pending.as_bytes().to_vec();
/// # let _ = (open, spare);
/// # Ok::<(), ws_pmd::CodecError>(())
/// ```
///
/// Reading it before the commit is the supported order:
///
/// ```
/// # use http::{header::SEC_WEBSOCKET_EXTENSIONS, HeaderMap, HeaderValue};
/// # use ws_pmd::{ClientConfig, ClientOffer, EncoderConfig, PmdComposition};
/// # let mut request = HeaderMap::new();
/// # let offer = ClientOffer::install(ClientConfig::new(), &mut request)
/// #     .expect("a fresh map");
/// # let mut response = HeaderMap::new();
/// # response.append(
/// #     SEC_WEBSOCKET_EXTENSIONS,
/// #     HeaderValue::from_static("permessage-deflate"),
/// # );
/// # let (mut encoder, _decoder) = offer
/// #     .seal(&request)
/// #     .expect("the offer is unchanged")
/// #     .finish(&response, PmdComposition::Compatible)
/// #     .expect("the response is legal")
/// #     .expect("the server selected it")
/// #     .into_codecs(EncoderConfig::new());
/// let open = encoder.begin_streaming_message()?;
/// let pending = open.prepare_non_final_fragment(b"first")?;
/// let spare = pending.as_bytes().to_vec();
/// let (_bytes, open) = pending.commit();
/// # let _ = (open, spare);
/// # Ok::<(), ws_pmd::CodecError>(())
/// ```
#[must_use = "an unresolved streaming message poisons the encoder"]
#[derive(Debug)]
pub struct StreamingMessage<'encoder> {
    encoder: &'encoder mut Encoder,
    compressor: Compress,
}

impl<'encoder> StreamingMessage<'encoder> {
    /// Compress the next chunk into a fragment that is not the last.
    ///
    /// RFC 7692 section 7.2.1 steps 1 and 2 only. Step 3 -- removing the
    /// terminal `00 00 ff ff` -- is what the section's MUST NOT forbids here, so
    /// every trailer this produces stays in the returned bytes and goes on the
    /// wire. The host frames these as a data frame with RSV1 and FIN clear, or a
    /// continuation frame, and never sets FIN.
    ///
    /// An empty chunk is legal and is a real fragment: the host is declaring a
    /// boundary, and the empty WebSocket continuation frame it produces is one
    /// the peer must accept. What comes back depends on position rather than on
    /// input -- the five-octet trailer from a compressor that has not just
    /// flushed, no bytes at all from one that has -- and both are conforming. A
    /// source that is *temporarily* empty is not a boundary: skip the call and
    /// wait for bytes, or call
    /// [`prepare_final_fragment`](Self::prepare_final_fragment) at end of
    /// source.
    ///
    /// Failing here poisons the encoder, the same as dropping the stream.
    pub fn prepare_non_final_fragment(
        self,
        payload: &[u8],
    ) -> Result<PreparedNonFinalFragment<'encoder>, CodecError> {
        let Self { encoder, mut compressor } = self;
        // As in `prepare_message`: the error path drops `compressor` here, and
        // that is what makes the failure terminal without a flag to maintain.
        let bytes = produce_non_final(&mut compressor, payload)?;
        Ok(PreparedNonFinalFragment { encoder, compressor, bytes })
    }

    /// Compress the last chunk and end the message.
    ///
    /// All three steps, exactly as [`Encoder::prepare_message`] runs them over a
    /// whole message: the terminal `00 00 ff ff` is removed here and only here,
    /// and a chunk that produces nothing becomes RFC 7692 section 7.2.3.6's
    /// single `0x00` octet. The host frames the result with FIN set.
    ///
    /// Consuming the stream is what ends the message. There is no state to
    /// continue from afterwards, so a fragment after FIN is not something to
    /// reject at runtime -- it does not typecheck.
    pub fn prepare_final_fragment(
        self,
        payload: &[u8],
    ) -> Result<PreparedFinalFragment<'encoder>, CodecError> {
        let Self { encoder, mut compressor } = self;
        let bytes = produce(&mut compressor, payload)?;
        Ok(PreparedFinalFragment { encoder, compressor, bytes })
    }
}

/// A non-final fragment that has not yet been declared sent.
///
/// The same transaction as [`PreparedMessage`], one fragment wide, and with no
/// discard arm: see [`StreamingMessage`] for why streaming has no
/// `reset_to_plain`.
#[must_use = "an unresolved fragment poisons the encoder"]
#[derive(Debug)]
pub struct PreparedNonFinalFragment<'encoder> {
    encoder: &'encoder mut Encoder,
    compressor: Compress,
    bytes: Vec<u8>,
}

impl<'encoder> PreparedNonFinalFragment<'encoder> {
    /// The candidate fragment payload, with every `00 00 ff ff` the flush
    /// produced still on it.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The candidate fragment payload, mutably, for a reversible transport
    /// transform such as client masking.
    #[must_use]
    pub fn as_bytes_mut(&mut self) -> &mut [u8] {
        &mut self.bytes
    }

    /// Declare that this fragment appeared on the wire, and take it along with
    /// the state that prepares the next one.
    ///
    /// Call it once the whole frame has been written, or inserted into a queue
    /// that cannot reject it -- reading the bytes is not sending them. That is
    /// as true of an empty fragment as of any other: the frame header is the
    /// boundary the peer sees, so commit follows the header rather than the
    /// payload.
    ///
    /// Never resets the compressor. `no_context_takeover` is negotiated per
    /// *message*, and this is the middle of one.
    ///
    /// # Discarding it
    ///
    /// The returned tuple carries the only value that can prepare the next
    /// fragment, so dropping it on the floor is the one mistake this shape
    /// cannot make unrepresentable. Under `deny(unused_must_use)` it is a build
    /// failure:
    ///
    /// ```compile_fail
    /// #![deny(unused_must_use)]
    /// # use http::{header::SEC_WEBSOCKET_EXTENSIONS, HeaderMap, HeaderValue};
    /// # use ws_pmd::{ClientConfig, ClientOffer, EncoderConfig, PmdComposition};
    /// # let mut request = HeaderMap::new();
    /// # let offer = ClientOffer::install(ClientConfig::new(), &mut request)
    /// #     .expect("a fresh map");
    /// # let mut response = HeaderMap::new();
    /// # response.append(
    /// #     SEC_WEBSOCKET_EXTENSIONS,
    /// #     HeaderValue::from_static("permessage-deflate"),
    /// # );
    /// # let (mut encoder, _decoder) = offer
    /// #     .seal(&request)
    /// #     .expect("the offer is unchanged")
    /// #     .finish(&response, PmdComposition::Compatible)
    /// #     .expect("the response is legal")
    /// #     .expect("the server selected it")
    /// #     .into_codecs(EncoderConfig::new());
    /// let open = encoder.begin_streaming_message()?;
    /// let pending = open.prepare_non_final_fragment(b"first")?;
    /// pending.commit();
    /// # Ok::<(), ws_pmd::CodecError>(())
    /// ```
    ///
    /// Binding both halves is all it takes:
    ///
    /// ```
    /// #![deny(unused_must_use)]
    /// # use http::{header::SEC_WEBSOCKET_EXTENSIONS, HeaderMap, HeaderValue};
    /// # use ws_pmd::{ClientConfig, ClientOffer, EncoderConfig, PmdComposition};
    /// # let mut request = HeaderMap::new();
    /// # let offer = ClientOffer::install(ClientConfig::new(), &mut request)
    /// #     .expect("a fresh map");
    /// # let mut response = HeaderMap::new();
    /// # response.append(
    /// #     SEC_WEBSOCKET_EXTENSIONS,
    /// #     HeaderValue::from_static("permessage-deflate"),
    /// # );
    /// # let (mut encoder, _decoder) = offer
    /// #     .seal(&request)
    /// #     .expect("the offer is unchanged")
    /// #     .finish(&response, PmdComposition::Compatible)
    /// #     .expect("the response is legal")
    /// #     .expect("the server selected it")
    /// #     .into_codecs(EncoderConfig::new());
    /// let open = encoder.begin_streaming_message()?;
    /// let pending = open.prepare_non_final_fragment(b"first")?;
    /// let (_bytes, _open) = pending.commit();
    /// # Ok::<(), ws_pmd::CodecError>(())
    /// ```
    #[must_use = "dropping the returned stream poisons the encoder"]
    pub fn commit(self) -> (Vec<u8>, StreamingMessage<'encoder>) {
        let Self { encoder, compressor, bytes } = self;
        (bytes, StreamingMessage { encoder, compressor })
    }
}

/// The last fragment of a streamed message, before it is declared sent.
///
/// Committing it is what restores the encoder, so this is the only state in the
/// streaming sequence whose resolution ends the message.
#[must_use = "an unresolved fragment poisons the encoder"]
#[derive(Debug)]
pub struct PreparedFinalFragment<'encoder> {
    encoder: &'encoder mut Encoder,
    compressor: Compress,
    bytes: Vec<u8>,
}

impl PreparedFinalFragment<'_> {
    /// The candidate final payload: the four-octet trailer already removed, or
    /// the RFC's `0x00` if the message ended without producing any.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The candidate final payload, mutably, for a reversible transport
    /// transform such as client masking.
    #[must_use]
    pub fn as_bytes_mut(&mut self) -> &mut [u8] {
        &mut self.bytes
    }

    /// Declare that the final fragment appeared on the wire, end the message,
    /// and return the encoder to a state that can start another.
    ///
    /// The negotiated `no_context_takeover` reset happens here, because here is
    /// where the message ends.
    #[must_use]
    pub fn commit(self) -> Vec<u8> {
        let Self { encoder, mut compressor, bytes } = self;
        if encoder.reset_between_messages {
            reset(&mut compressor);
        }
        encoder.compressor = Some(compressor);
        bytes
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

/// RFC 7692 section 7.2.1 steps 1 and 2, over one payload chunk.
///
/// Everything the two producers share, ending exactly where they stop agreeing:
/// a complete message and a final fragment go on to step 3, and a non-final
/// fragment is forbidden from it.
fn produce_aligned(compressor: &mut Compress, payload: &[u8]) -> Result<Vec<u8>, CodecError> {
    let room = room_for(payload.len());
    let mut output = Vec::new();
    feed(compressor, payload, &mut output, room)?;
    sync_flush(compressor, &mut output, room)?;
    Ok(output)
}

/// RFC 7692 section 7.2.1 steps 1 through 3, for one complete message or for the
/// final fragment of a streamed one.
fn produce(compressor: &mut Compress, payload: &[u8]) -> Result<Vec<u8>, CodecError> {
    let output = produce_aligned(compressor, payload)?;
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

/// Steps 1 and 2 with step 3 deliberately not run, for a fragment that is not
/// the last.
///
/// RFC 7692 section 7.2.1: the trailer "MUST NOT" be removed from a non-final
/// fragment, so every `00 00 ff ff` the flush produced is kept -- including a
/// mid-payload one, which is why this checks a tail and never searches.
///
/// The one case with no tail to check is a chunk the backend answered with
/// nothing. That happens for empty input after a flush that has already drained
/// the compressor, and it is legal: the fragment carries no payload and the
/// frame header is what marks the boundary. No bytes for a chunk that *had*
/// bytes is a fault, exactly as it is for a whole message.
fn produce_non_final(compressor: &mut Compress, payload: &[u8]) -> Result<Vec<u8>, CodecError> {
    let mut fragment = produce_aligned(compressor, payload)?;
    let aligned = fragment.ends_with(TRAILER) || (payload.is_empty() && fragment.is_empty());
    if !aligned {
        return Err(CodecError::CompressionFailed);
    }
    // The same reservation slack, given back for the same reason as in `produce`.
    fragment.shrink_to_fit();
    Ok(fragment)
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
/// because that is zlib's documented protocol for a flush that did not fit.
///
/// Two different rounds can fill the room, and only one of them is a problem. An
/// *intermediate* round -- the backend still holds pending output -- has to be
/// repeated, and the repeat drains what is left; that is the case this loop
/// exists for, and it was measured: zlib-rs at level 1 with a 4,096-byte chunk
/// on macOS/aarch64 took two rounds, `(4,160, 4,160)` then `(167, 4,160)`, and
/// came out byte-identical to the same code given effectively unbounded room, so
/// the repeat drained pending output and added nothing. A *completing* round that
/// happens to fill the room exactly is the ambiguous one: zlib cannot signal
/// "complete" apart from "the buffer filled exactly", so it sets
/// `last_flush = -1` and the repeat becomes a *new* sync flush, which on an
/// already-drained stream appends a second empty stored block. [`BLOCK_ROOM`] is
/// what keeps a completing call from ever being that round; the loop remains for
/// a backend holding more pending output than that, which would get the
/// redundant block -- valid wire, never a wrong stream.
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
