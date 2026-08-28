//! RFC 7692 `permessage-deflate`, independent of any WebSocket implementation.
//!
//! This crate owns two things: whether the extension was correctly negotiated,
//! and the per-connection DEFLATE state that follows. It owns nothing else. It
//! has no socket, no runtime, no frame type, and no opinion about masking,
//! opcodes, close codes, UTF-8, or message assembly — those stay with the host.
//!
//! # Handshake
//!
//! Both roles are state machines whose types enforce their order, so a host
//! cannot build compression state from anything but a finalized agreement.
//!
//! A client installs an offer, seals it against the request that is actually
//! being sent, then applies the response:
//!
//! ```
//! use http::HeaderMap;
//! use ws_pmd::{ClientConfig, ClientOffer, PmdComposition};
//!
//! let mut request = HeaderMap::new();
//! let offer = ClientOffer::install(ClientConfig::new(), &mut request)?;
//!
//! // The host finishes building the request, then seals at the send boundary.
//! let handshake = offer.seal(&request)?;
//!
//! let mut response = HeaderMap::new();
//! response.insert(
//!     http::header::SEC_WEBSOCKET_EXTENSIONS,
//!     "permessage-deflate; server_max_window_bits=12".parse().unwrap(),
//! );
//! // The host states, from its own final selected extension set, that nothing
//! // else on this connection conflicts with permessage-deflate.
//! let negotiated = handshake
//!     .finish(&response, PmdComposition::Compatible)?
//!     .expect("the server selected it");
//! assert_eq!(negotiated.peer_max_window_bits(), 12);
//! assert_eq!(negotiated.local_max_window_bits(), 15);
//! # Ok::<(), ws_pmd::NegotiationError>(())
//! ```
//!
//! A client that deliberately offered nothing seals that fact instead, with
//! [`ClientHandshake::seal_without_offer`], and gets an error rather than an
//! agreement if the server selects `permessage-deflate` anyway.
//!
//! A server selects an alternative, hands the host the exact response element,
//! and commits only once that element survived the host's own callbacks.
//!
//! # Malformed headers
//!
//! Both receive points -- [`ServerHandshake::accept`] for a request and
//! [`ClientHandshake::finish`] for a response -- check the whole
//! `Sec-WebSocket-Extensions` field against the RFC 6455 section 9.1 grammar
//! before interpreting any of it, including extension elements this crate knows
//! nothing about. A `MalformedHeader` error means the host must fail the
//! opening handshake, which is what section 9.1 requires of the recipient; it
//! is not a decline and must not be handled as one. Declining is `Ok(None)`.
//!
//! Extension and parameter names are compared exactly. Neither RFC asks for
//! case folding here, so `Permessage-Deflate` is a conforming extension name
//! that this crate does not implement -- `Ok(None)`, not an error.
//!
//! # Windows
//!
//! RFC 7692 names its parameters after the server and the client. Which one is
//! "this side" depends on the role, so [`Negotiated`] reports `local` and `peer`
//! instead and keeps the mapping private. A peer window of 8 is legal and is
//! reported as 8; only building an inflater raises it to 9, which is flate2's
//! floor for both directions, and a wider inflater accepts every stream a
//! narrower compressor emits. A local compressor window is never 8 and never
//! clamped: it is rejected where it is configured.

mod client;
mod codec;
mod config;
mod encoder;
mod error;
mod grammar;
mod negotiated;
mod server;

pub use client::{ClientHandshake, ClientOffer};
pub use codec::{Decoder, DecompressedLimit};
pub use config::{ClientConfig, EncoderConfig, ServerConfig};
pub use encoder::{
    Encoder, PreparedFinalFragment, PreparedMessage, PreparedNonFinalFragment, StreamingMessage,
};
pub use error::{CodecError, ConfigError, NegotiationError};
pub use negotiated::{Negotiated, PmdComposition};
pub use server::ServerHandshake;
