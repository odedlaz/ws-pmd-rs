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
        Decoder {
            // A negotiated peer window of 8 is legal and is reported as 8, but
            // flate2 will not build an inflater below 9. Widening is safe in
            // this direction only: a wider window accepts every stream a
            // narrower compressor can emit. The agreement is never rewritten.
            inflater: Decompress::new_with_window_bits(
                false,
                self.peer_max_window_bits().max(MIN_INFLATER_WINDOW_BITS),
            ),
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
                self.inflater.reset(false);
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
            let remaining = limit.0.saturating_sub(produced_so_far);
            // The `+ 1` is the whole detector. Leaving room for exactly one byte
            // past the ceiling means the overrun is observed as it is produced
            // rather than after a full scratch buffer has been materialised, so
            // a bomb is stopped during inflate. `remaining` saturates at zero:
            // once the ceiling has fallen below what was already delivered, that
            // one byte is past the delivery, not past the ceiling.
            let writable = remaining.saturating_add(1).min(scratch.len());
            let before = (self.inflater.total_in(), self.inflater.total_out());
            #[expect(
                clippy::indexing_slicing,
                reason = "`writable` is `min`-ed with `scratch.len()` where it is bound"
            )]
            let status = self
                .inflater
                .decompress(input, &mut scratch[..writable], FlushDecompress::None)
                .map_err(|_| CodecError::InvalidStream)?;
            let consumed = advance(before.0, self.inflater.total_in(), input.len());
            let produced = advance(before.1, self.inflater.total_out(), writable);

            #[expect(
                clippy::indexing_slicing,
                reason = "`advance` clamps to `writable`, itself within scratch.len()"
            )]
            output.extend_from_slice(&scratch[..produced]);
            let size = self.delivered.saturating_add(output.len());
            if size > limit.0 {
                return Err(CodecError::MessageTooLong { size, limit: limit.0 });
            }
            #[expect(
                clippy::indexing_slicing,
                reason = "`advance` clamps to the `input.len()` it was handed"
            )]
            let unconsumed = &input[consumed..];
            input = unconsumed;

            if status == Status::StreamEnd {
                // The peer flushed with BFINAL set, which ends the DEFLATE
                // stream (RFC 7692 section 7.2.3.4 permits this). A peer that
                // does it must start a new stream, which cannot reference the
                // old window, so resetting mirrors it. Without this the inflater
                // stays finished and every later message decodes to nothing.
                self.inflater.reset(false);
            }
            if !progress(consumed, produced, !input.is_empty())? {
                return Ok(());
            }
        }
    }
}

/// One backend call moves its `total_*` counter by at most the length of the
/// buffer it was handed, so clamping the `u64` delta to that length is exact
/// rather than lossy — and it keeps a fallible cast out of the hot loop.
fn advance(before: u64, after: u64, buffer_len: usize) -> usize {
    usize::try_from(after.saturating_sub(before)).unwrap_or(buffer_len).min(buffer_len)
}

/// Whether the backend moved, given what it did and what is left to give it.
///
/// Keyed on residual input, not on the status, because no status answers the
/// question. `Ok` is permitted when more input is unavailable, so treating it
/// as a stall can fail a conforming backend; and neither `BufError` nor
/// `StreamEnd` proves the slice was drained, so treating them as ordinary
/// termination can drop a tail in silence. What distinguishes a stall from an
/// exit is whether there was anything left for the call to work on.
const fn progress(
    consumed: usize,
    produced: usize,
    input_remains: bool,
) -> Result<bool, CodecError> {
    if consumed != 0 || produced != 0 {
        return Ok(true);
    }
    if input_remains {
        return Err(CodecError::Stalled);
    }
    Ok(false)
}

#[cfg(test)]
#[expect(clippy::panic, reason = "a panic is how a test reports")]
mod tests {
    use super::{advance, progress, CodecError};

    /// Exhaustive: three progress shapes against both residual states is the
    /// whole input space of the function, now that the status is not part of it.
    ///
    /// It has to be pinned here because no driven row reaches the two cases that
    /// matter. Across the suite, every zero-progress point is `BufError` with
    /// the input drained -- the one combination both the old rule and this one
    /// answer the same way. So the two mutants worth fearing are invisible to
    /// the integration tests in opposite ways: deleting the guard makes the
    /// codec spin, and `cargo test` has no per-test timeout, so the row that
    /// should go red never finishes; forcing `input_remains` to false makes it
    /// exit early and drop a tail in silence, with every row still green.
    #[test]
    fn a_stall_is_zero_progress_with_input_still_to_read() {
        for (consumed, produced, input_remains, expected) in [
            (0, 0, false, Some(false)),
            (0, 0, true, None),
            (1, 0, false, Some(true)),
            (1, 0, true, Some(true)),
            (0, 1, false, Some(true)),
            (0, 1, true, Some(true)),
        ] {
            let got = progress(consumed, produced, input_remains);
            match (got, expected) {
                (Ok(got), Some(want)) => {
                    assert_eq!(got, want, "progress({consumed}, {produced}, {input_remains})");
                }
                (Err(CodecError::Stalled), None) => {}
                (got, want) => panic!(
                    "progress({consumed}, {produced}, {input_remains}) gave {got:?}, wanted {want:?}"
                ),
            }
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
