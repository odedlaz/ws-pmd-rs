//! Typed negotiation failures.

/// Why a `permessage-deflate` handshake produced no agreement.
///
/// Variants stay separate where RFC 7692 section 7 separates them, so a host can
/// tell a peer that broke the grammar from one that answered with a selection it
/// was never offered. No compression-backend error is reachable from here.
///
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum NegotiationError {
    /// A `Sec-WebSocket-Extensions` value violated the header grammar: an
    /// unterminated quoted string, a trailing escape, or a bare `"` inside an
    /// unquoted parameter value.
    #[error("malformed Sec-WebSocket-Extensions value")]
    MalformedHeader,

    /// A `permessage-deflate` element carried a parameter RFC 7692 does not
    /// define. Unrelated extensions are not parsed and cannot raise this.
    #[error("unknown permessage-deflate parameter")]
    UnknownParameter,

    /// A `permessage-deflate` element repeated one of the four parameters.
    #[error("duplicate permessage-deflate parameter")]
    DuplicateParameter,

    /// A window-bits value was malformed, leading-zero padded, or outside 8..=15.
    #[error("window bits must be 8 through 15 without leading zeros")]
    InvalidWindowBits,

    /// A `no_context_takeover` parameter carried a value, or a
    /// `server_max_window_bits` parameter carried none.
    #[error("permessage-deflate parameter has the wrong arity")]
    ParameterArity,

    /// `permessage-deflate` appeared more than once where one selection is
    /// required.
    #[error("permessage-deflate selected more than once")]
    DuplicateExtension,

    /// The client required `server_no_context_takeover` and the response did not
    /// confirm it.
    #[error("server_no_context_takeover was required, not confirmed")]
    ServerTakeoverNotHonoured,

    /// The client offered a bounded `server_max_window_bits` and the response
    /// omitted it, so the server's compressor window is unconfirmed.
    #[error("server_max_window_bits was offered bounded, not confirmed")]
    ServerWindowUnconfirmed,

    /// The response widened `server_max_window_bits` past the offered bound.
    #[error("server_max_window_bits exceeds the offered bound")]
    ServerWindowTooLarge,

    /// The response demanded a `client_max_window_bits` below 9, which is
    /// narrower than any compressor this side can be built at.
    ///
    /// A *wider* response value is not an error. RFC 7692 section 7.1.2.2 makes
    /// the offered value a hint the server may ignore, binds the client to it
    /// regardless of the answer, and puts no MUST NOT on a larger response — so
    /// the agreement narrows to the offer instead of failing the handshake.
    #[error("client_max_window_bits is below the 9-bit floor a compressor needs")]
    ClientWindowTooNarrow,

    /// The response carried a valueless `client_max_window_bits`. The valueless
    /// form is an offer-only signal; a response must state the chosen width.
    #[error("client_max_window_bits must carry a value in a response")]
    ClientWindowValueless,

    /// The request already carried a caller-installed `permessage-deflate`
    /// offer when the crate was asked to install its own, or to seal a request
    /// as carrying none.
    #[error("the request already carries a permessage-deflate offer")]
    OfferCollision,

    /// The server selected `permessage-deflate` against a request that never
    /// offered it. RFC 7692 section 7.1 lets a server select only from what the
    /// client offered, so this is the peer breaking the protocol.
    #[error("the response selected permessage-deflate, which was never offered")]
    UnsolicitedExtension,

    /// The request that reached the send boundary no longer carries exactly the
    /// offer that was installed: it was removed, rewritten, or duplicated.
    #[error("the final request does not carry the installed offer")]
    OfferAltered,

    /// The response that reached the serialization boundary is not byte-for-byte
    /// the selection handed to the host. Version 0.1 permits the exact proposal
    /// or removal, and nothing between.
    #[error("the final response is not the proposed selection")]
    ResponseAltered,

    /// `permessage-deflate` was selected alongside an extension the host says it
    /// cannot compose with under RFC 7692 section 5. The host attests to this at
    /// the same boundary that commits the response, so a conflicting set fails
    /// before any codec exists rather than at the first compressed frame.
    #[error("a selected extension does not compose with permessage-deflate")]
    ExtensionConflict,
}

/// Why a compressed message could not be turned back into bytes.
///
/// Every variant is terminal for its direction. The split that matters is
/// [`MessageTooLong`](Self::MessageTooLong) against the rest: a host maps that
/// one to whatever it already does for an over-capacity message, close code
/// 1009, while the others say the peer's stream or this side's state is broken.
/// No compression-backend error type is reachable from here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum CodecError {
    /// The message decompressed past the ceiling the host supplied.
    ///
    /// `size` is one past `limit` only while the ceiling never fell below the
    /// bytes already delivered for this message: the detector leaves room for
    /// one byte past whichever of the two is higher. A host that lowers its
    /// capacity between fragments is told `size` one past what was already
    /// delivered, which can exceed `limit` by any amount — so nothing may be
    /// derived from `size - limit`.
    #[error("message decompressed to {size} bytes, over the {limit} allowed")]
    MessageTooLong {
        /// The decompressed bytes this message had produced when it was stopped.
        size: usize,
        /// The ceiling that was in force for the call that stopped it.
        limit: usize,
    },

    /// The compressed bytes are not a valid DEFLATE stream, or are not the
    /// stream this connection's history says they should be.
    #[error("invalid DEFLATE stream")]
    InvalidStream,

    /// The backend reported success while consuming and producing nothing. A
    /// caller that trusted it would spin forever, so it is an error here.
    #[error("the compression backend stopped making progress")]
    Stalled,

    /// This direction already failed. The peer's compressor and this side's
    /// history are no longer in step, so there is nothing to resume.
    #[error("this direction has already failed")]
    Poisoned,
}

/// Why a locally supplied value was rejected before it could reach a backend.
///
/// Configuration is validated where it is set, so an out-of-range window can
/// never reach a builder that would panic on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ConfigError {
    /// A local compressor window outside 9..=15. Values are never clamped: 8 is
    /// rejected here rather than silently widened, because a peer that agreed to
    /// 8 would inflate against a window this side never used.
    #[error("local compressor window bits must be 9 through 15")]
    WindowBits,

    /// A bound on the peer's compressor outside 8..=15. Eight is legal to ask
    /// for; only building a local inflater for it clamps to 9.
    #[error("peer compressor window bits must be 8 through 15")]
    PeerWindowBits,
}
