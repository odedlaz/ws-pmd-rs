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
pub enum Role {
    Client,
    Server,
}

/// Whether every other extension this connection selected can compose with
/// `permessage-deflate`.
///
/// `Compatible` asserts one fact about the connection's **final selected**
/// extension set — not what was offered: every other selected extension is
/// composition-compatible with `permessage-deflate` under RFC 7692 section 5.
/// None conflicts on RSV1, and no extension whose output feeds
/// `permessage-deflate` requires preserved frame boundaries or uses Extension
/// data or reserved bits as per-frame attributes.
///
/// The crate cannot check this itself: RFC 7692 forbids orderings across
/// extensions it has no way to see, and reading them would need the extension
/// registry version 0.1 deliberately does not have. So the host states the fact
/// and the type system forces it to. A required argument is the whole mechanism
/// — a token this crate handed out would be forgeable and would prove no more.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PmdComposition {
    /// No other selected extension conflicts with `permessage-deflate`.
    Compatible,
    /// Some other selected extension does. No agreement may be produced.
    Conflict,
}

/// A settled `permessage-deflate` agreement.
///
/// Holds settings, not compression state, and allocates nothing. It is
/// deliberately neither `Copy` nor `Clone`: codecs are built by consuming it,
/// and that is only a gate if the value cannot be spent twice. A `Copy`
/// agreement made double-minting invisible -- `n.into_decoder()` twice
/// compiled, with no syntactic marker that anything unusual had happened.
#[derive(Debug, PartialEq, Eq)]
pub struct Negotiated {
    role: Role,
    server_no_context_takeover: bool,
    client_no_context_takeover: bool,
    server_max_window_bits: u8,
    client_max_window_bits: u8,
}

impl Negotiated {
    pub(crate) const fn new(
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
pub enum ClientBits {
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
pub fn render(
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
    #[expect(
        clippy::expect_used,
        reason = "render_is_always_valid exhausts this function's input space"
    )]
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
