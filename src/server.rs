//! The server half of the handshake.
//!
//! A server reads alternatives in the order the client wrote them and takes the
//! first it can support. Declining is not failing: an offer this crate cannot
//! honour leaves the connection uncompressed, which is always a legal outcome.
//! Only a response that contradicts what the server itself proposed is an error.

use http::{header::SEC_WEBSOCKET_EXTENSIONS, HeaderMap, HeaderValue};

use crate::config::ServerConfig;
use crate::error::NegotiationError;
use crate::grammar::{self, ClientWindow, Params};
use crate::negotiated::{render, ClientBits, Negotiated, PmdComposition, Role};

const MAX_WINDOW_BITS: u8 = 15;

/// A selection the server has made but not yet committed to the wire.
#[derive(Debug, Clone)]
pub struct ServerHandshake {
    proposed: HeaderValue,
    agreement: Negotiated,
}

impl ServerHandshake {
    /// Choose the first supportable `permessage-deflate` alternative.
    ///
    /// Returns `None` when the request offers none, offers only alternatives
    /// this configuration cannot honour, or carries a `Sec-WebSocket-Extensions`
    /// value that does not parse. A server declines rather than rejecting the
    /// whole upgrade, because refusing a connection over an extension it was
    /// never going to use turns a malformed header into a denial of service.
    #[must_use]
    pub fn accept(config: ServerConfig, headers: &HeaderMap) -> Option<Self> {
        for value in headers.get_all(SEC_WEBSOCKET_EXTENSIONS) {
            let Ok(elements) = grammar::elements(value.as_bytes()) else {
                return None;
            };
            for element in elements {
                if grammar::is_blank(element) {
                    continue;
                }
                match grammar::is_deflate(element) {
                    Ok(true) => {}
                    Ok(false) => continue,
                    // Unreadable bytes get no answer. This signature has no
                    // shape in which to say so, so it declines instead.
                    Err(_) => return None,
                }
                // A single unsupported alternative declines itself; the client
                // may have written a weaker one after it.
                let Ok(offer) = grammar::parse_params(element) else {
                    continue;
                };
                if let Some(accepted) = select(config, offer) {
                    return Some(accepted);
                }
            }
        }
        None
    }

    /// The exact response element the host must emit for this selection.
    #[must_use]
    pub fn value(&self) -> &HeaderValue {
        &self.proposed
    }

    /// Commit the selection against the response the host actually built.
    ///
    /// Returns `None` if a callback removed the extension, which is the host
    /// changing its mind and is allowed. Any other difference is an error:
    /// version 0.1 commits the header and the runtime state together, so a
    /// rewritten response — even to another selection these offers permit —
    /// would leave codecs configured for a wire contract nobody sent.
    ///
    /// A server that wants to decline a conflicting extension set cleanly
    /// removes `permessage-deflate` from the response first, which is the
    /// ordinary removal path. Passing [`PmdComposition::Conflict`] with the
    /// selection still in place is a bug in the host, and it aborts.
    pub fn finish(
        self,
        headers: &HeaderMap,
        composition: PmdComposition,
    ) -> Result<Option<Negotiated>, NegotiationError> {
        let mut found = 0usize;
        for value in headers.get_all(SEC_WEBSOCKET_EXTENSIONS) {
            for element in grammar::elements(value.as_bytes())? {
                if !grammar::is_deflate(element)? {
                    continue;
                }
                found += 1;
                if grammar::trim(element) != self.proposed.as_bytes() {
                    return Err(NegotiationError::ResponseAltered);
                }
            }
        }
        match found {
            0 => Ok(None),
            1 if composition == PmdComposition::Conflict => {
                Err(NegotiationError::ExtensionConflict)
            }
            1 => Ok(Some(self.agreement)),
            _ => Err(NegotiationError::ResponseAltered),
        }
    }
}

/// RFC 7692 section 7.1 from the server's side: narrow every parameter to what
/// both ends can hold, or decline the alternative.
fn select(config: ServerConfig, offer: Params) -> Option<ServerHandshake> {
    let server_no_context_takeover =
        config.imposes_server_no_context_takeover() || offer.server_no_context_takeover;
    let client_no_context_takeover =
        config.imposes_client_no_context_takeover() || offer.client_no_context_takeover;

    // server_max_window_bits bounds this server's own compressor, and no
    // compressor can be built at 8. Declining leaves the door open for a
    // weaker alternative rather than agreeing to a width we cannot honour.
    let server_window = match offer.server_max_window_bits {
        Some(8) => return None,
        Some(bits) => Some(bits.min(config.supported_server_max_window_bits())),
        None if config.supported_server_max_window_bits() < MAX_WINDOW_BITS => {
            Some(config.supported_server_max_window_bits())
        }
        None => None,
    };

    // Bounding the client's window is only legal if the client said it
    // understands the parameter. An absent offer with a bound to impose is an
    // alternative this server cannot express, not one it can silently widen.
    let client_window = match offer.client_max_window_bits {
        ClientWindow::Absent if config.supported_client_max_window_bits() < MAX_WINDOW_BITS => {
            return None
        }
        ClientWindow::Absent => None,
        ClientWindow::Valueless => Some(config.supported_client_max_window_bits()),
        ClientWindow::Bits(bits) => Some(bits.min(config.supported_client_max_window_bits())),
    };

    let proposed = render(
        server_no_context_takeover,
        client_no_context_takeover,
        server_window,
        // Full width is the default, so echoing it would add a parameter that
        // says nothing. The peer's 8 is carried through unchanged.
        &client_window
            .filter(|bits| *bits < MAX_WINDOW_BITS)
            .map_or(ClientBits::Omit, ClientBits::Bits),
    );

    let agreement = Negotiated::new(
        Role::Server,
        server_no_context_takeover,
        client_no_context_takeover,
        server_window.unwrap_or(MAX_WINDOW_BITS),
        client_window.unwrap_or(MAX_WINDOW_BITS),
    );
    Some(ServerHandshake { proposed, agreement })
}
