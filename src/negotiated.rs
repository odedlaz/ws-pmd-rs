//! The finalized agreement, and the wire rendering both roles share.

use http::HeaderValue;

use crate::grammar::NAME;

/// Which end of the connection holds this agreement.
///
/// RFC 7692 names its parameters after the server and the client, so the same
/// field is local policy for one side and a description of the peer for the
/// other. Keeping the role private lets callers ask about "this side" and "the
/// other side" without re-deriving the mapping at every call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Role {
    Client,
    Server,
}

/// A settled `permessage-deflate` agreement.
///
/// Holds settings, not compression state: it is cheap to copy and allocates
/// nothing. Codecs are built by consuming it, which is the only way to reach
/// active compression state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Negotiated {
    role: Role,
    server_no_context_takeover: bool,
    client_no_context_takeover: bool,
    server_max_window_bits: u8,
    client_max_window_bits: u8,
}

impl Negotiated {
    pub(crate) fn new(
        role: Role,
        server_no_context_takeover: bool,
        client_no_context_takeover: bool,
        server_max_window_bits: u8,
        client_max_window_bits: u8,
    ) -> Self {
        Self {
            role,
            server_no_context_takeover,
            client_no_context_takeover,
            server_max_window_bits,
            client_max_window_bits,
        }
    }

    /// Whether this side must drop its compression history between messages.
    #[must_use]
    pub fn local_no_context_takeover(&self) -> bool {
        match self.role {
            Role::Client => self.client_no_context_takeover,
            Role::Server => self.server_no_context_takeover,
        }
    }

    /// Whether the peer drops its compression history between messages.
    #[must_use]
    pub fn peer_no_context_takeover(&self) -> bool {
        match self.role {
            Role::Client => self.server_no_context_takeover,
            Role::Server => self.client_no_context_takeover,
        }
    }

    /// The window this side's compressor may use. Always at least 9.
    #[must_use]
    pub fn local_max_window_bits(&self) -> u8 {
        match self.role {
            Role::Client => self.client_max_window_bits,
            Role::Server => self.server_max_window_bits,
        }
    }

    /// The window the peer's compressor may use, exactly as negotiated.
    ///
    /// This can be 8. The value is reported unchanged; only building a local
    /// inflater for it raises it to 9, because zlib has no 8-bit inflater. That
    /// is safe in one direction only: a wider inflater window accepts every
    /// stream a narrower compressor can produce.
    #[must_use]
    pub fn peer_max_window_bits(&self) -> u8 {
        match self.role {
            Role::Client => self.server_max_window_bits,
            Role::Server => self.client_max_window_bits,
        }
    }
}

/// The `client_max_window_bits` form to render.
pub(crate) enum ClientBits {
    /// Omit the parameter.
    Omit,
    /// Emit it with no value. Legal in an offer only.
    Valueless,
    /// Emit it with an explicit width.
    Bits(u8),
}

/// Render one `permessage-deflate` element.
///
/// Every byte comes from a fixed token or an ASCII digit, so the result is
/// always a valid `HeaderValue`; `render_is_always_valid` proves it across every
/// reachable combination.
pub(crate) fn render(
    server_no_context_takeover: bool,
    client_no_context_takeover: bool,
    server_max_window_bits: Option<u8>,
    client_max_window_bits: &ClientBits,
) -> HeaderValue {
    let mut value = String::from(NAME);
    if server_no_context_takeover {
        value.push_str("; server_no_context_takeover");
    }
    if client_no_context_takeover {
        value.push_str("; client_no_context_takeover");
    }
    if let Some(bits) = server_max_window_bits {
        value.push_str("; server_max_window_bits=");
        value.push_str(&bits.to_string());
    }
    match client_max_window_bits {
        ClientBits::Omit => {}
        ClientBits::Valueless => value.push_str("; client_max_window_bits"),
        ClientBits::Bits(bits) => {
            value.push_str("; client_max_window_bits=");
            value.push_str(&bits.to_string());
        }
    }
    HeaderValue::from_str(&value).expect("every rendered byte is a fixed token or an ASCII digit")
}

#[cfg(test)]
mod tests {
    use super::{render, ClientBits};

    /// The one `expect` in the crate's production path. Exhaust its input space
    /// rather than reason about it.
    #[test]
    fn render_is_always_valid() {
        let client_forms = [ClientBits::Omit, ClientBits::Valueless]
            .into_iter()
            .chain((8..=15).map(ClientBits::Bits));
        let mut count = 0;
        for client in client_forms {
            for server in core::iter::once(None).chain((8..=15).map(Some)) {
                for server_takeover in [false, true] {
                    for client_takeover in [false, true] {
                        let value = render(server_takeover, client_takeover, server, &client);
                        assert!(value.to_str().is_ok());
                        count += 1;
                    }
                }
            }
        }
        assert_eq!(count, 10 * 9 * 2 * 2);
    }
}
