//! Per-connection DEFLATE state, and the ceiling that bounds what it produces.
//!
//! RFC 7692 sends raw DEFLATE with the four-byte empty-block trailer
//! `00 00 ff ff` stripped from the tail of every message. The decoder therefore
//! feeds that trailer back before it can see the end of a message, which is why
//! the final fragment is a parameter rather than something the bytes reveal.
//!
//! Nothing here knows about frames. The host decides which payloads belong to
//! one message and routes control frames past the codec entirely; a call that
//! never happens cannot disturb the state.

use flate2::{Decompress, FlushDecompress, Status};

use crate::error::CodecError;
use crate::negotiated::Negotiated;

/// The trailer RFC 7692 section 7.2.1 strips from every compressed message.
const TRAILER: &[u8] = &[0x00, 0x00, 0xff, 0xff];

/// Output taken from the backend per call, and the stack this decoder costs
/// while one is in flight.
///
/// One hard constraint: at least 1. The ceiling detector asks the backend for
/// one byte past the remaining allowance, so a zero-length buffer makes every
/// call produce nothing and the stall guard reports a backend that never
/// moved. Measured, not argued -- at 0 the codec suite fails 22 of 23 rows, at
/// 1 and at 16 it passes all 23. Everything above 1 trades backend round trips
/// against stack, and correctness does not depend on where in that range this
/// sits. 4096 is the value the extraction source used.
const SCRATCH: usize = 4096;

/// The narrowest inflater `flate2` will construct.
///
/// `Decompress::new_with_window_bits` asserts `9 ..= 15` in flate2's own
/// frontend (`mem.rs:420-423`), before any backend sees the value, so this is
/// an API contract rather than a property of zlib. Whether some backend could
/// inflate at 8 is not a question this crate can ask through flate2.
const MIN_INFLATER_WINDOW_BITS: u8 = 9;

/// The width `Decompress::reset` reinitialises at, whatever the stream was
/// built with.
///
/// `reset` takes no window bits: zlib-rs rebuilds from
/// `InflateConfig::default()` and the C backend passes
/// `±MZ_DEFAULT_WINDOW_BITS` to `inflateReset2`. Both are 15, so a reset keeps
/// the negotiated window at exactly this width and discards it at every other.
const DEFAULT_INFLATER_WINDOW_BITS: u8 = 15;

/// A finite ceiling on the decompressed bytes one message may produce.
///
/// This bounds one quantity: the bytes a message has accumulated across all of
/// its fragments. It is not a frame-size limit and it is not this crate's copy
/// of the host's wire-input limit — a host keeps that separate guard on the
/// compressed bytes, with its own operand and its own comparison. Exactly this
/// many bytes are allowed; the byte after is an error.
///
/// There is no unbounded spelling. A host whose plain-message setting is
/// unbounded supplies a finite limit while `permessage-deflate` is active,
/// because compressed input is the one path where a small frame can ask for
/// arbitrary memory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct DecompressedLimit(usize);

impl DecompressedLimit {
    /// Allow a message to decompress to at most `bytes`.
    #[must_use]
    pub const fn bytes(bytes: usize) -> Self {
        Self(bytes)
    }
}

/// Everything the inflater is built from, kept so that rebuilding it is the
/// same operation as building it.
///
/// `flate2` offers no width-preserving reset below 15, so a narrower negotiated
/// window survives exactly until the first reinitialisation unless this crate
/// rebuilds from what it stored.
///
/// What the width buys is backend-dependent, and both arms are measured. zlib-rs
/// sizes its window `1 << MAX_WBITS` whatever it is told, so the declared width
/// changes neither decoding nor allocation there. C zlib sizes it `1 << wbits`
/// at first use, so the width both bounds memory -- 512 bytes against 32 KiB --
/// and is enforced while decoding, where a back-reference past it fails the
/// stream. Cargo features are additive, so a downstream graph selects which.
///
/// Losing the width widens the inflater, which is the lenient direction: it goes
/// on accepting every stream the peer may legally send. What a lost width costs
/// is the negotiated memory bound, not decoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct InflaterConfig {
    zlib_header: bool,
    window_bits: u8,
}

impl InflaterConfig {
    /// RFC 7692 messages are raw DEFLATE, and a peer window of 8 is legal on
    /// the wire but below the floor `flate2` will construct.
    const fn for_peer_window(peer_max_window_bits: u8) -> Self {
        Self {
            zlib_header: false,
            window_bits: if peer_max_window_bits < MIN_INFLATER_WINDOW_BITS {
                MIN_INFLATER_WINDOW_BITS
            } else {
                peer_max_window_bits
            },
        }
    }

    /// The only place this crate constructs an inflater.
    fn build(self) -> Decompress {
        Decompress::new_with_window_bits(self.zlib_header, self.window_bits)
    }

    /// Whether `Decompress::reset` reinitialises at this configuration's own
    /// width, which is the only case where it may be used.
    const fn resets_in_place(self) -> bool {
        self.window_bits == DEFAULT_INFLATER_WINDOW_BITS
    }

    /// Start `inflater` over on a fresh message, keeping the negotiated window.
    ///
    /// `reset` preserves the width at the backend default and nowhere else, and
    /// there it is the cheaper route on both backends: it allocates nothing,
    /// where rebuilding takes a fresh allocation. Below that width rebuilding is
    /// the only route that keeps the width, and on C zlib it is the cheaper one
    /// too, because `reset` frees the narrow window and re-widens to 15 on next
    /// use. flate2 offers no third route.
    ///
    /// Which of the two runs is unguarded: swapping them survives the whole
    /// suite. `resets_in_place` is pinned, its use here is not, and nothing
    /// downstream can see the difference -- the one instrument that can, counting
    /// the global allocator, needs the `unsafe` this crate forbids.
    fn reinitialise(self, inflater: &mut Decompress) {
        if self.resets_in_place() {
            #[expect(
                clippy::disallowed_methods,
                reason = "the one width where reset keeps the configuration, pinned by `the_reset_route_is_taken_only_where_it_preserves_the_width`"
            )]
            inflater.reset(self.zlib_header);
        } else {
            *inflater = self.build();
        }
    }
}

/// The inflater for one connection, in one direction.
///
/// Holds the peer's decompression history and the running total for the message
/// being assembled. The total lives here rather than at the call site so a host
/// cannot under-report a fragmented message by forgetting to accumulate.
///
/// Every failure is terminal. An invalid stream, a stalled backend and an
/// over-long message all poison the decoder, because the WebSocket connection
/// is already required to fail: resuming would be a recovery contract this crate
/// cannot honour, since the peer's compressor has moved on either way.
#[derive(Debug)]
pub struct Decoder {
    config: InflaterConfig,
    inflater: Decompress,
    reset_between_messages: bool,
    delivered: usize,
    poisoned: bool,
}

impl Negotiated {
    /// Build the inflater this agreement describes.
    ///
    /// The first point that allocates zlib state, and the only way to reach it:
    /// there is no constructor that turns local configuration into a live codec.
    /// It consumes the agreement, and [`Negotiated`] is neither `Copy` nor
    /// `Clone`, so one agreement mints one codec.
    ///
    /// ```
    /// # use http::{header::SEC_WEBSOCKET_EXTENSIONS, HeaderMap, HeaderValue};
    /// # use permessage_deflate::{ClientConfig, ClientOffer, PmdComposition};
    /// # let mut request = HeaderMap::new();
    /// # let offer = ClientOffer::install(ClientConfig::new(), &mut request)?;
    /// # let mut response = HeaderMap::new();
    /// # response.append(
    /// #     SEC_WEBSOCKET_EXTENSIONS,
    /// #     HeaderValue::from_static("permessage-deflate"),
    /// # );
    /// # let agreed = offer.seal(&request)?.finish(&response, PmdComposition::Compatible)?
    /// #     .expect("the server selected it");
    /// let decoder = agreed.into_decoder();
    /// # Ok::<(), permessage_deflate::NegotiationError>(())
    /// ```
    ///
    /// Spending the same agreement twice does not compile. The example above is
    /// the control for this one: they differ by exactly the second call.
    ///
    /// ```compile_fail
    /// # use http::{header::SEC_WEBSOCKET_EXTENSIONS, HeaderMap, HeaderValue};
    /// # use permessage_deflate::{ClientConfig, ClientOffer, PmdComposition};
    /// # let mut request = HeaderMap::new();
    /// # let offer = ClientOffer::install(ClientConfig::new(), &mut request)?;
    /// # let mut response = HeaderMap::new();
    /// # response.append(
    /// #     SEC_WEBSOCKET_EXTENSIONS,
    /// #     HeaderValue::from_static("permessage-deflate"),
    /// # );
    /// # let agreed = offer.seal(&request)?.finish(&response, PmdComposition::Compatible)?
    /// #     .expect("the server selected it");
    /// let decoder = agreed.into_decoder();
    /// let another = agreed.into_decoder();
    /// # Ok::<(), permessage_deflate::NegotiationError>(())
    /// ```
    #[must_use]
    pub fn into_decoder(self) -> Decoder {
        let config = InflaterConfig::for_peer_window(self.peer_max_window_bits());
        Decoder {
            config,
            inflater: config.build(),
            reset_between_messages: self.peer_no_context_takeover(),
            delivered: 0,
            poisoned: false,
        }
    }
}

impl Decoder {
    /// Decompress one fragment of the current message.
    ///
    /// `final_fragment` marks the last fragment the host will pass for this
    /// message; the limit is read fresh on every call, so a host that lowers its
    /// capacity mid-connection is obeyed from the next fragment onward rather
    /// than at whatever value negotiation happened to see.
    pub fn decompress(
        &mut self,
        input: &[u8],
        final_fragment: bool,
        limit: DecompressedLimit,
    ) -> Result<Vec<u8>, CodecError> {
        if self.poisoned {
            return Err(CodecError::Poisoned);
        }
        let mut output = Vec::new();
        match self.decode(input, final_fragment, limit, &mut output) {
            Ok(()) => {
                self.delivered =
                    if final_fragment { 0 } else { self.delivered.saturating_add(output.len()) };
                Ok(output)
            }
            Err(error) => {
                self.poisoned = true;
                Err(error)
            }
        }
    }

    fn decode(
        &mut self,
        input: &[u8],
        final_fragment: bool,
        limit: DecompressedLimit,
        output: &mut Vec<u8>,
    ) -> Result<(), CodecError> {
        self.inflate(input, limit, output)?;
        if final_fragment {
            self.inflate(TRAILER, limit, output)?;
            if self.reset_between_messages {
                self.config.reinitialise(&mut self.inflater);
            }
        }
        Ok(())
    }

    fn inflate(
        &mut self,
        mut input: &[u8],
        limit: DecompressedLimit,
        output: &mut Vec<u8>,
    ) -> Result<(), CodecError> {
        let mut scratch = [0u8; SCRATCH];
        loop {
            let produced_so_far = self.delivered.saturating_add(output.len());
            let allowance = limit.0.saturating_sub(produced_so_far);
            // The `+ 1` is the whole detector. Leaving room for exactly one byte
            // past the ceiling means the overrun is observed as it is produced
            // rather than after a full scratch buffer has been materialised, so
            // a bomb is stopped during inflate. `allowance` saturates at zero:
            // once the ceiling has fallen below what was already delivered, that
            // one byte is past the delivery, not past the ceiling.
            let writable = allowance.saturating_add(1).min(scratch.len());
            #[expect(
                clippy::indexing_slicing,
                reason = "`writable` is `min`-ed with `scratch.len()` where it is bound"
            )]
            let step = step(&mut self.inflater, input, &mut scratch[..writable])?;

            #[expect(
                clippy::indexing_slicing,
                reason = "`step` clamps `produced` to the scratch it was handed"
            )]
            output.extend_from_slice(&scratch[..step.produced]);
            let size = self.delivered.saturating_add(output.len());
            if size > limit.0 {
                return Err(CodecError::MessageTooLong { size, limit: limit.0 });
            }
            if step.stream_ended {
                // The peer flushed with BFINAL set, which ends the DEFLATE
                // stream (RFC 7692 section 7.2.3.4 permits this). A peer that
                // does it must start a new stream, which cannot reference the
                // old window, so resetting mirrors it. Without this the inflater
                // stays finished and every later message decodes to nothing.
                self.config.reinitialise(&mut self.inflater);
            }
            match step.remaining {
                Some(rest) => input = rest,
                None => return Ok(()),
            }
        }
    }
}

/// What one backend call did, derived from the slice that call was handed.
struct Step<'a> {
    produced: usize,
    /// What is left of the input, or `None` once the backend has stopped moving
    /// and there is nothing left to feed it.
    remaining: Option<&'a [u8]>,
    stream_ended: bool,
}

/// One backend call moves its `total_*` counter by at most the length of the
/// buffer it was handed, so clamping the `u64` delta to that length is exact
/// rather than lossy — and it keeps a fallible cast out of the hot loop.
fn advance(before: u64, after: u64, buffer_len: usize) -> usize {
    usize::try_from(after.saturating_sub(before)).unwrap_or(buffer_len).min(buffer_len)
}

/// Drive the backend once, and read the outcome off the slice it was given.
///
/// The input arrives here once and goes straight to `decompress`, so the
/// residual and the stall verdict come from the same bytes the backend saw. The
/// caller gets a transition rather than the operands to recompute one from, and
/// has no second slice or flag it could pass inconsistently.
///
/// A stall is zero progress with input still to read, keyed on the residual and
/// not on the status, because no status answers the question. `Ok` is permitted
/// when more input is unavailable, so treating it as a stall can fail a
/// conforming backend; and neither `BufError` nor `StreamEnd` proves the slice
/// was drained, so treating them as ordinary termination can drop a tail in
/// silence.
fn step<'a>(
    inflater: &mut Decompress,
    input: &'a [u8],
    scratch: &mut [u8],
) -> Result<Step<'a>, CodecError> {
    let before = (inflater.total_in(), inflater.total_out());
    let status = inflater
        .decompress(input, scratch, FlushDecompress::None)
        .map_err(|_| CodecError::InvalidStream)?;
    let consumed = advance(before.0, inflater.total_in(), input.len());
    let produced = advance(before.1, inflater.total_out(), scratch.len());
    #[expect(
        clippy::indexing_slicing,
        reason = "`advance` clamps to the `input.len()` it was handed"
    )]
    let unconsumed = &input[consumed..];
    let remaining = if consumed != 0 || produced != 0 {
        Some(unconsumed)
    } else if unconsumed.is_empty() {
        None
    } else {
        return Err(CodecError::Stalled);
    };
    Ok(Step { produced, remaining, stream_ended: status == Status::StreamEnd })
}

#[cfg(test)]
#[expect(clippy::panic, clippy::expect_used, reason = "a panic is how a test reports")]
mod tests {
    use flate2::{Compress, Compression, FlushCompress};

    use super::{advance, step, CodecError, InflaterConfig, DEFAULT_INFLATER_WINDOW_BITS};
    use crate::negotiated::{Negotiated, Role};

    /// A raw DEFLATE stream ending in BFINAL, from an independent compressor.
    fn raw_deflate(plain: &[u8]) -> Vec<u8> {
        let mut compressor = Compress::new_with_window_bits(Compression::default(), false, 15);
        let mut wire = vec![0u8; plain.len() + 64];
        compressor.compress(plain, &mut wire, FlushCompress::Finish).expect("one buffer is enough");
        wire.truncate(usize::try_from(compressor.total_out()).expect("smaller than the buffer"));
        wire
    }

    /// The transition one backend call produces, including the one class no
    /// driven row reaches.
    ///
    /// Zero progress with input still to read cannot happen through the codec:
    /// production always leaves room for at least one byte, so every
    /// zero-progress point in the suite is drained. A zero-length scratch
    /// reaches it here through the real backend rather than a stubbed one. It
    /// has to be reached somewhere -- a deleted stall guard makes the codec
    /// spin, and `cargo test` has no per-test timeout, so the row that should
    /// go red never returns at all.
    #[test]
    fn a_step_stalls_only_with_input_still_to_read() {
        let wire = raw_deflate(b"hello, hello, hello");
        let mut scratch = [0u8; 64];

        let mut inflater = InflaterConfig::for_peer_window(15).build();
        let decoded = step(&mut inflater, &wire, &mut scratch).expect("a whole message decodes");
        assert!(decoded.produced > 0, "the call moved");
        assert_eq!(decoded.remaining, Some(&[][..]), "drained, but the call moved");
        assert!(decoded.stream_ended, "the wire ends with BFINAL");

        let idle = step(&mut inflater, &[], &mut scratch).expect("an idle call is not a stall");
        assert_eq!(idle.produced, 0);
        assert!(idle.remaining.is_none(), "nothing left to feed it, so the loop must exit");

        // A zero-length scratch does not stall the backend on the first call --
        // it consumes header bytes without producing any -- so drive it until it
        // cannot move at all. The residual shrinks whenever it consumes, and
        // zero progress with input left is the error, so this terminates either
        // way rather than spinning.
        let long = raw_deflate(&b"stall me, stall me, stall me, ".repeat(256));
        let mut starved = InflaterConfig::for_peer_window(15).build();
        let mut unread = &long[..];
        let outcome = loop {
            match step(&mut starved, unread, &mut []) {
                Ok(moved) => match moved.remaining {
                    Some(rest) if !rest.is_empty() => unread = rest,
                    _ => break Ok(()),
                },
                Err(error) => break Err(error),
            }
        };
        assert_eq!(
            outcome,
            Err(CodecError::Stalled),
            "input left and the backend cannot move: the tail would be dropped in silence"
        );
    }

    /// Which reinitialisation route each negotiable width takes.
    ///
    /// `reset` keeps the negotiated window only where the configuration already
    /// is the backend default, so exactly one width may take it. This pins the
    /// predicate, which is why the `reset` call site names this row; it does not
    /// pin `reinitialise` consulting it in the right direction, and nothing
    /// reachable from here can.
    #[test]
    fn the_reset_route_is_taken_only_where_it_preserves_the_width() {
        for peer in 8..=15u8 {
            let config = InflaterConfig::for_peer_window(peer);
            assert_eq!(
                config.resets_in_place(),
                config.window_bits == DEFAULT_INFLATER_WINDOW_BITS,
                "peer {peer} built at {} bits",
                config.window_bits
            );
        }
        assert!(InflaterConfig::for_peer_window(15).resets_in_place(), "15 resets");
        assert!(!InflaterConfig::for_peer_window(14).resets_in_place(), "14 rebuilds");
        assert!(!InflaterConfig::for_peer_window(8).resets_in_place(), "the 8-to-9 clamp rebuilds");
    }

    /// The arguments the production factory hands `flate2`, for every peer
    /// width both roles can negotiate.
    ///
    /// Read off the `Decoder` a real agreement built, not off a helper called
    /// beside it. Both roles, because `peer_max_window_bits` reads the opposite
    /// stored field in each and a direction swap is otherwise invisible: with
    /// one role the two fields would only have to agree.
    ///
    /// This is a mapping and state seam, not a claim about the arguments
    /// `flate2` receives. A literal substituted inside `build` still passes it,
    /// and nothing downstream can see the difference: `Decompress` exposes no
    /// width read-back, and on the pinned backend the width changes neither
    /// decoding nor allocation. Those substitutions are unguarded and recorded
    /// as such rather than described as covered.
    #[test]
    fn the_inflater_is_built_at_the_negotiated_peer_width_for_both_roles() {
        for peer in 8..=15u8 {
            let expected = InflaterConfig {
                zlib_header: false,
                window_bits: if peer == 8 { 9 } else { peer },
            };
            // Role::Client reads server_max_window_bits as the peer's; the
            // local field is set to a different value so a swap shows up.
            let client = Negotiated::new(Role::Client, false, false, peer, 15 - (peer - 8));
            assert_eq!(client.into_decoder().config, expected, "client, peer {peer}");

            let server = Negotiated::new(Role::Server, false, false, 15 - (peer - 8), peer);
            assert_eq!(server.into_decoder().config, expected, "server, peer {peer}");
        }
    }

    /// The clamp is load-bearing on a 32-bit target, where a `u64` delta has
    /// somewhere to overflow to. The rows either side of the buffer length are
    /// what distinguish an exact clamp from a truncating cast.
    #[test]
    fn a_counter_delta_is_clamped_to_the_buffer_it_came_from() {
        assert_eq!(advance(0, 0, 4096), 0, "a call that did nothing");
        assert_eq!(advance(7, 4103, 4096), 4096, "a call that filled the buffer");
        assert_eq!(advance(0, 5, 4096), 5, "the ordinary partial case");
        assert_eq!(advance(0, u64::MAX, 4096), 4096, "a delta beyond the buffer cannot pass");
        assert_eq!(advance(9, 4, 4096), 0, "a counter that reset under us must not underflow");
    }
}
