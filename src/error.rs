//! Typed negotiation failures.

use core::fmt;

/// Why a `permessage-deflate` handshake produced no agreement.
///
/// Variants stay separate where RFC 7692 section 7 separates them, so a host can
/// tell a peer that broke the grammar from one that answered with a selection it
/// was never offered. No compression-backend error is reachable from here.
///
/// There is no "unsolicited selection" variant. A response can only be applied
/// through a sealed offer, so with the single alternative version 0.1 emits, a
/// selection that was never offered is always some specific disagreement with
/// that offer and is reported as that. Offering ordered alternatives would make
/// the distinction real and reintroduce it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum NegotiationError {
    /// A `Sec-WebSocket-Extensions` value violated the header grammar: an
    /// unterminated quoted string, a trailing escape, or an empty element name.
    MalformedHeader,

    /// A `permessage-deflate` element carried a parameter RFC 7692 does not
    /// define. Unrelated extensions are not parsed and cannot raise this.
    UnknownParameter,

    /// A `permessage-deflate` element repeated one of the four parameters.
    DuplicateParameter,

    /// A window-bits value was malformed, leading-zero padded, or outside 8..=15.
    InvalidWindowBits,

    /// A `no_context_takeover` parameter carried a value, or a
    /// `server_max_window_bits` parameter carried none.
    ParameterArity,

    /// `permessage-deflate` appeared more than once where one selection is
    /// required.
    DuplicateExtension,

    /// The client required `server_no_context_takeover` and the response did not
    /// confirm it.
    ServerTakeoverNotHonoured,

    /// The client offered a bounded `server_max_window_bits` and the response
    /// omitted it, so the server's compressor window is unconfirmed.
    ServerWindowUnconfirmed,

    /// The response widened `server_max_window_bits` past the offered bound.
    ServerWindowTooLarge,

    /// The response set `client_max_window_bits` to a value the client never
    /// offered, or below the 9-bit floor its compressor can be built at.
    ClientWindowNotOffered,

    /// The response carried a valueless `client_max_window_bits`. The valueless
    /// form is an offer-only signal; a response must state the chosen width.
    ClientWindowValueless,

    /// The request already carried a caller-installed `permessage-deflate` offer
    /// when the crate was asked to install its own.
    OfferCollision,

    /// The request that reached the send boundary no longer carries exactly the
    /// offer that was installed: it was removed, rewritten, or duplicated.
    OfferAltered,

    /// The response that reached the serialization boundary is not byte-for-byte
    /// the selection handed to the host. Version 0.1 permits the exact proposal
    /// or removal, and nothing between.
    ResponseAltered,

    /// `permessage-deflate` was selected alongside an extension the host says it
    /// cannot compose with under RFC 7692 section 5. The host attests to this at
    /// the same boundary that commits the response, so a conflicting set fails
    /// before any codec exists rather than at the first compressed frame.
    ExtensionConflict,
}

impl fmt::Display for NegotiationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::MalformedHeader => "malformed Sec-WebSocket-Extensions value",
            Self::UnknownParameter => "unknown permessage-deflate parameter",
            Self::DuplicateParameter => "duplicate permessage-deflate parameter",
            Self::InvalidWindowBits => "window bits must be 8 through 15 without leading zeros",
            Self::ParameterArity => "permessage-deflate parameter has the wrong arity",
            Self::DuplicateExtension => "permessage-deflate selected more than once",
            Self::ServerTakeoverNotHonoured => {
                "server_no_context_takeover was required, not confirmed"
            }
            Self::ServerWindowUnconfirmed => {
                "server_max_window_bits was offered bounded, not confirmed"
            }
            Self::ServerWindowTooLarge => "server_max_window_bits exceeds the offered bound",
            Self::ClientWindowNotOffered => "client_max_window_bits was not offered",
            Self::ClientWindowValueless => {
                "client_max_window_bits must carry a value in a response"
            }
            Self::OfferCollision => "the request already carries a permessage-deflate offer",
            Self::OfferAltered => "the final request does not carry the installed offer",
            Self::ResponseAltered => "the final response is not the proposed selection",
            Self::ExtensionConflict => {
                "a selected extension does not compose with permessage-deflate"
            }
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for NegotiationError {}

/// Why a compressed message could not be turned back into bytes.
///
/// Every variant is terminal for its direction. The split that matters is
/// [`MessageTooLong`](Self::MessageTooLong) against the rest: a host maps that
/// one to whatever it already does for an over-capacity message, close code
/// 1009, while the others say the peer's stream or this side's state is broken.
/// No compression-backend error type is reachable from here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CodecError {
    /// The message decompressed past the ceiling the host supplied. `size` is
    /// always exactly one byte past `limit`, because that byte is what detects
    /// the overrun: the decoder never accumulates a chunk beyond the ceiling to
    /// find out it went over.
    MessageTooLong {
        /// The decompressed bytes this message had produced when it was stopped.
        size: usize,
        /// The ceiling that was in force for the call that stopped it.
        limit: usize,
    },

    /// The compressed bytes are not a valid DEFLATE stream, or are not the
    /// stream this connection's history says they should be.
    InvalidStream,

    /// The backend reported success while consuming and producing nothing. A
    /// caller that trusted it would spin forever, so it is an error here.
    Stalled,

    /// This direction already failed. The peer's compressor and this side's
    /// history are no longer in step, so there is nothing to resume.
    Poisoned,
}

impl fmt::Display for CodecError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MessageTooLong { size, limit } => {
                write!(formatter, "message decompressed to {size} bytes, over the {limit} allowed")
            }
            Self::InvalidStream => formatter.write_str("invalid DEFLATE stream"),
            Self::Stalled => formatter.write_str("the compression backend stopped making progress"),
            Self::Poisoned => formatter.write_str("this direction has already failed"),
        }
    }
}

impl std::error::Error for CodecError {}

/// Why a locally supplied value was rejected before it could reach a backend.
///
/// Configuration is validated where it is set, so an out-of-range window can
/// never reach a builder that would panic on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ConfigError {
    /// A local compressor window outside 9..=15. Values are never clamped: 8 is
    /// rejected here rather than silently widened, because a peer that agreed to
    /// 8 would inflate against a window this side never used.
    WindowBits,

    /// A bound on the peer's compressor outside 8..=15. Eight is legal to ask
    /// for; only building a local inflater for it clamps to 9.
    PeerWindowBits,
}

impl fmt::Display for ConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::WindowBits => "local compressor window bits must be 9 through 15",
            Self::PeerWindowBits => "peer compressor window bits must be 8 through 15",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for ConfigError {}
