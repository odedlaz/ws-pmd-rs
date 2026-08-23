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

/// Output taken from the backend per call. Matches the extraction source.
const SCRATCH: usize = 4096;

/// The narrowest inflater zlib can build.
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
    #[must_use]
    pub fn into_decoder(self) -> Decoder {
        Decoder {
            // A negotiated peer window of 8 is legal and is reported as 8, but
            // zlib has no 8-bit inflater. Widening is safe in this direction
            // only: a wider window accepts every stream a narrower compressor
            // can emit. The agreement itself is never rewritten.
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
            // past the ceiling means the overrun is observed as it is produced,
            // rather than after a full scratch buffer has been materialised, so
            // a bomb is stopped during inflate and the reported size is always
            // one over rather than up to a chunk over.
            let writable = remaining.saturating_add(1).min(scratch.len());
            let before = (self.inflater.total_in(), self.inflater.total_out());
            let status = self
                .inflater
                .decompress(input, &mut scratch[..writable], FlushDecompress::None)
                .map_err(|_| CodecError::InvalidStream)?;
            let consumed = advance(before.0, self.inflater.total_in(), input.len());
            let produced = advance(before.1, self.inflater.total_out(), writable);

            output.extend_from_slice(&scratch[..produced]);
            let size = self.delivered.saturating_add(output.len());
            if size > limit.0 {
                return Err(CodecError::MessageTooLong { size, limit: limit.0 });
            }
            input = &input[consumed..];

            if status == Status::StreamEnd {
                // The peer flushed with BFINAL set, which ends the DEFLATE
                // stream (RFC 7692 section 7.2.3.4 permits this). A peer that
                // does it must start a new stream, which cannot reference the
                // old window, so resetting mirrors it. Without this the inflater
                // stays finished and every later message decodes to nothing.
                self.inflater.reset(false);
            }
            if !progress(status, consumed, produced)? {
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

/// Whether the backend moved, given what it claimed and what it did.
///
/// Zero progress reported as success is the stall: the caller would spin on it
/// forever. Zero progress with `BufError` or `StreamEnd` is ordinary
/// termination — out of input, out of room, or done.
fn progress(status: Status, consumed: usize, produced: usize) -> Result<bool, CodecError> {
    if consumed != 0 || produced != 0 {
        return Ok(true);
    }
    match status {
        Status::Ok => Err(CodecError::Stalled),
        Status::BufError | Status::StreamEnd => Ok(false),
    }
}

#[cfg(test)]
mod tests {
    use super::{advance, progress, CodecError, Status};

    /// A driven loop cannot prove this: a mutant that deletes the guard makes
    /// the codec hang, and `cargo test` has no per-test timeout, so the row that
    /// should go red never finishes. Pinning the pure function instead means the
    /// same mutant fails a test in milliseconds.
    #[test]
    fn zero_progress_reported_as_success_is_the_only_stall() {
        for (status, consumed, produced, expected) in [
            (Status::Ok, 0, 0, None),
            (Status::Ok, 1, 0, Some(true)),
            (Status::Ok, 0, 1, Some(true)),
            (Status::BufError, 0, 0, Some(false)),
            (Status::BufError, 1, 0, Some(true)),
            (Status::BufError, 0, 1, Some(true)),
            (Status::StreamEnd, 0, 0, Some(false)),
            (Status::StreamEnd, 1, 0, Some(true)),
            (Status::StreamEnd, 0, 1, Some(true)),
        ] {
            match (progress(status, consumed, produced), expected) {
                (Ok(got), Some(want)) => {
                    assert_eq!(got, want, "progress({status:?}, {consumed}, {produced})");
                }
                (Err(CodecError::Stalled), None) => {}
                (got, want) => panic!(
                    "progress({status:?}, {consumed}, {produced}) gave {got:?}, wanted {want:?}"
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
