//! Local policy. Cheap to build; nothing here allocates compression state.
//!
//! The two roles get separate types because the same RFC 7692 parameter names a
//! different compressor depending on who reads it. `server_max_window_bits`
//! bounds the server's compressor: that is local policy for a server and a
//! demand on the peer for a client. The window a side can actually build starts
//! at 9, so the two directions validate against different floors.

use crate::error::ConfigError;

/// The widest window DEFLATE defines, and the value that means "unbounded" in an
/// offer, where the parameter is then omitted.
const MAX_WINDOW_BITS: u8 = 15;

/// The narrowest window a compressor can be built for. RFC 7692 admits 8 on the
/// wire, but zlib cannot construct an 8-bit compressor.
const MIN_LOCAL_WINDOW_BITS: u8 = 9;

/// The narrowest window that may appear on the wire.
const MIN_WIRE_WINDOW_BITS: u8 = 8;

fn check_local(bits: u8) -> Result<u8, ConfigError> {
    if (MIN_LOCAL_WINDOW_BITS..=MAX_WINDOW_BITS).contains(&bits) {
        Ok(bits)
    } else {
        Err(ConfigError::WindowBits)
    }
}

fn check_peer(bits: u8) -> Result<u8, ConfigError> {
    if (MIN_WIRE_WINDOW_BITS..=MAX_WINDOW_BITS).contains(&bits) {
        Ok(bits)
    } else {
        Err(ConfigError::PeerWindowBits)
    }
}

/// What a client asks for, and what it will insist on.
///
/// Every field is a hard requirement. A client that would rather have a setting
/// but will proceed without it must offer both alternatives explicitly; version
/// 0.1 exposes no preference flag, because a boolean cannot render the ordered
/// fallback offer RFC 7692 defines for that case.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientConfig {
    server_no_context_takeover: bool,
    client_no_context_takeover: bool,
    server_max_window_bits: u8,
    client_max_window_bits: u8,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            server_no_context_takeover: false,
            client_no_context_takeover: false,
            server_max_window_bits: MAX_WINDOW_BITS,
            client_max_window_bits: MAX_WINDOW_BITS,
        }
    }
}

impl ClientConfig {
    /// A client that requires no takeover limits and no window bounds.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Require the server to drop its compression history between messages.
    #[must_use]
    pub fn server_no_context_takeover(mut self, required: bool) -> Self {
        self.server_no_context_takeover = required;
        self
    }

    /// Volunteer to drop this client's compression history between messages.
    ///
    /// A server may impose this even when it is not volunteered, so the agreed
    /// value can be stricter than what was offered.
    #[must_use]
    pub fn client_no_context_takeover(mut self, offered: bool) -> Self {
        self.client_no_context_takeover = offered;
        self
    }

    /// Bound the server's compressor window. This is the peer's compressor, so 8
    /// is a legal request even though no local compressor can be built at 8.
    pub fn server_max_window_bits(mut self, bits: u8) -> Result<Self, ConfigError> {
        self.server_max_window_bits = check_peer(bits)?;
        Ok(self)
    }

    /// Bound this client's own compressor window.
    pub fn client_max_window_bits(mut self, bits: u8) -> Result<Self, ConfigError> {
        self.client_max_window_bits = check_local(bits)?;
        Ok(self)
    }

    pub(crate) const fn requires_server_no_context_takeover(self) -> bool {
        self.server_no_context_takeover
    }

    pub(crate) const fn offers_client_no_context_takeover(self) -> bool {
        self.client_no_context_takeover
    }

    pub(crate) const fn offered_server_max_window_bits(self) -> u8 {
        self.server_max_window_bits
    }

    pub(crate) const fn offered_client_max_window_bits(self) -> u8 {
        self.client_max_window_bits
    }
}

/// What a server can support, and what it will impose.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServerConfig {
    server_no_context_takeover: bool,
    client_no_context_takeover: bool,
    server_max_window_bits: u8,
    client_max_window_bits: u8,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            server_no_context_takeover: false,
            client_no_context_takeover: false,
            server_max_window_bits: MAX_WINDOW_BITS,
            client_max_window_bits: MAX_WINDOW_BITS,
        }
    }
}

impl ServerConfig {
    /// A server that imposes no takeover limits and no window bounds.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Drop this server's compression history between messages, whether or not
    /// the client asked for it.
    #[must_use]
    pub fn server_no_context_takeover(mut self, imposed: bool) -> Self {
        self.server_no_context_takeover = imposed;
        self
    }

    /// Require the client to drop its compression history between messages.
    #[must_use]
    pub fn client_no_context_takeover(mut self, imposed: bool) -> Self {
        self.client_no_context_takeover = imposed;
        self
    }

    /// Bound this server's own compressor window.
    pub fn server_max_window_bits(mut self, bits: u8) -> Result<Self, ConfigError> {
        self.server_max_window_bits = check_local(bits)?;
        Ok(self)
    }

    /// Bound the client's compressor window. This is the peer's compressor, so 8
    /// is acceptable and is carried through to the response unchanged.
    pub fn client_max_window_bits(mut self, bits: u8) -> Result<Self, ConfigError> {
        self.client_max_window_bits = check_peer(bits)?;
        Ok(self)
    }

    pub(crate) const fn imposes_server_no_context_takeover(self) -> bool {
        self.server_no_context_takeover
    }

    pub(crate) const fn imposes_client_no_context_takeover(self) -> bool {
        self.client_no_context_takeover
    }

    pub(crate) const fn supported_server_max_window_bits(self) -> u8 {
        self.server_max_window_bits
    }

    pub(crate) const fn supported_client_max_window_bits(self) -> u8 {
        self.client_max_window_bits
    }
}
