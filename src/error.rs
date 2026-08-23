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
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for NegotiationError {}

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
