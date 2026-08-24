//! The client half of the handshake.
//!
//! Each type is the proof that the step before it ran. [`ClientOffer`] holds
//! what was installed in the request; a [`ClientHandshake`] exists only once
//! the request that is actually being sent has been checked -- either against
//! that offer, or against the absence of one -- and only a sealed handshake can
//! produce a [`Negotiated`].
//! Nothing here consults [`ClientConfig`] to decide what went on the wire — the
//! sealed offer is the record, because a host is free to rewrite headers after
//! the crate has installed them.
//!
//! A host that deliberately offered nothing enters at
//! [`ClientHandshake::seal_without_offer`], which proves that and nothing else.
//! The same `finish` then reports an unsolicited selection rather than an
//! agreement, so the RFC rule is closed once here instead of in every host.

use http::{header::SEC_WEBSOCKET_EXTENSIONS, HeaderMap, HeaderValue};

use crate::config::ClientConfig;
use crate::error::NegotiationError;
use crate::grammar::{self, ClientWindow, Params};
use crate::negotiated::{render, ClientBits, Negotiated, PmdComposition, Role};

/// The widest window, which is also the value an offer omits.
const MAX_WINDOW_BITS: u8 = 15;

/// A `permessage-deflate` offer installed in a request that has not been sent.
#[derive(Debug)]
pub struct ClientOffer {
    config: ClientConfig,
    installed: HeaderValue,
}

/// A request confirmed against the exact headers leaving the host. Only this
/// value can finish a handshake, whether or not it carries an offer.
#[derive(Debug)]
pub struct ClientHandshake {
    /// `None` once [`seal_without_offer`](ClientHandshake::seal_without_offer)
    /// has proved the request carried no offer at all.
    offer: Option<SealedOffer>,
}

#[derive(Debug)]
struct SealedOffer {
    config: ClientConfig,
    sealed: HeaderValue,
}

impl ClientOffer {
    /// Append this crate's offer to the request.
    ///
    /// Fails if the request already carries a `permessage-deflate` element: two
    /// offers on one wire means two components believe they own the extension,
    /// and silently winning that race is how a host ends up with compression
    /// state that does not match its headers.
    pub fn install(
        config: ClientConfig,
        headers: &mut HeaderMap,
    ) -> Result<Self, NegotiationError> {
        if contains_deflate(headers)? {
            return Err(NegotiationError::OfferCollision);
        }
        let installed = render_offer(config);
        headers.append(SEC_WEBSOCKET_EXTENSIONS, installed.clone());
        Ok(Self { config, installed })
    }

    /// The element this offer installed, for a host that must log or mirror it.
    #[must_use]
    pub fn value(&self) -> &HeaderValue {
        &self.installed
    }

    /// Confirm the offer survived request construction, at the boundary where
    /// the host is about to serialize.
    ///
    /// Removal, rewriting, and duplication are all rejected here rather than
    /// discovered later as a correspondence failure against a response.
    pub fn seal(self, headers: &HeaderMap) -> Result<ClientHandshake, NegotiationError> {
        let mut found = 0usize;
        for value in headers.get_all(SEC_WEBSOCKET_EXTENSIONS) {
            for element in grammar::elements(value.as_bytes())? {
                if !grammar::is_deflate(element)? {
                    continue;
                }
                found += 1;
                if grammar::trim(element) != self.installed.as_bytes() {
                    return Err(NegotiationError::OfferAltered);
                }
            }
        }
        if found != 1 {
            return Err(NegotiationError::OfferAltered);
        }
        Ok(ClientHandshake {
            offer: Some(SealedOffer { config: self.config, sealed: self.installed }),
        })
    }
}

impl ClientHandshake {
    /// Seal a request that deliberately carries no `permessage-deflate` offer.
    ///
    /// RFC 6455 section 9 forbids a server responding with an extension the
    /// client did not request, and RFC 7692 section 5 makes failing the
    /// connection this side's MUST when one does. The client is the only side
    /// that can see it, and without this entry the crate never sees such a
    /// request -- it only ever holds state it installed into -- so the rule
    /// would fall to every host separately.
    ///
    /// Fails with [`OfferCollision`](NegotiationError::OfferCollision) if the
    /// request does carry an offer, because then this is the wrong state for
    /// these headers and the check that follows would be answering about a
    /// request that does not exist.
    pub fn seal_without_offer(headers: &HeaderMap) -> Result<Self, NegotiationError> {
        if contains_deflate(headers)? {
            return Err(NegotiationError::OfferCollision);
        }
        Ok(Self { offer: None })
    }

    /// The offer that crossed the send boundary, if the request carried one.
    #[must_use]
    pub fn value(&self) -> Option<&HeaderValue> {
        self.offer.as_ref().map(|offer| &offer.sealed)
    }

    /// Apply the response to the sealed offer.
    ///
    /// Returns `None` when the server declined the extension, which is a normal
    /// outcome and not an error. `composition` is only consulted once the server
    /// has actually selected `permessage-deflate`: a connection that ended up
    /// without it has nothing to compose.
    ///
    /// The response may carry `Sec-WebSocket-Extensions` on more than one field
    /// line. RFC 6455 section 4.2.2 item 6 builds one that way, section 9.1 notes
    /// the field "MAY be split or combined across multiple lines", and verified
    /// erratum EID 3433 replaces section 11.3.2's MUST NOT with a MAY. Every line
    /// is read as one list, so a second `permessage-deflate` selection anywhere in
    /// it is a [`DuplicateExtension`](NegotiationError::DuplicateExtension) and a
    /// response naming only other extensions is an ordinary decline.
    pub fn finish(
        self,
        headers: &HeaderMap,
        composition: PmdComposition,
    ) -> Result<Option<Negotiated>, NegotiationError> {
        grammar::validate(headers)?;
        let Some(params) = sole_deflate(headers)? else {
            return Ok(None);
        };
        // A selection against no offer outranks a composition report, the same
        // way a rewritten response does on the server side: the peer broke the
        // protocol, and the host's account of its own extension set cannot
        // change that or make an agreement out of it.
        let Some(offer) = self.offer else {
            return Err(NegotiationError::UnsolicitedExtension);
        };
        if composition == PmdComposition::Conflict {
            return Err(NegotiationError::ExtensionConflict);
        }
        offer.agree(params).map(Some)
    }
}

impl SealedOffer {
    /// RFC 7692 section 7.1: the response refines the offer or the handshake fails.
    fn agree(&self, params: Params) -> Result<Negotiated, NegotiationError> {
        if self.config.requires_server_no_context_takeover() && !params.server_no_context_takeover {
            return Err(NegotiationError::ServerTakeoverNotHonoured);
        }

        // Union, not assignment: a server may impose client_no_context_takeover
        // the client never volunteered, and dropping the offered value here
        // would let this side keep history the peer has already discarded.
        let client_no_context_takeover =
            self.config.offers_client_no_context_takeover() || params.client_no_context_takeover;

        let offered_server = self.config.offered_server_max_window_bits();
        let server_max_window_bits = match params.server_max_window_bits {
            Some(bits) if bits > offered_server => {
                return Err(NegotiationError::ServerWindowTooLarge)
            }
            Some(bits) => bits,
            // A bounded offer must be answered. Silence would leave this side
            // inflating against a width the server never agreed to hold.
            None if offered_server < MAX_WINDOW_BITS => {
                return Err(NegotiationError::ServerWindowUnconfirmed)
            }
            None => MAX_WINDOW_BITS,
        };

        let offered_client = self.config.offered_client_max_window_bits();
        let client_max_window_bits = match params.client_max_window_bits {
            ClientWindow::Valueless => return Err(NegotiationError::ClientWindowValueless),
            ClientWindow::Bits(bits) if bits < 9 => {
                return Err(NegotiationError::ClientWindowTooNarrow)
            }
            // A wider answer is conforming: the offer is a hint the server may
            // ignore (RFC 7692 section 7.1.2.2), so rejecting it would fail a
            // legal peer. Holding to the offer anyway is policy, not the RFC --
            // section 7.2.1 would permit the agreed value -- and the policy is
            // that a configured bound stays configured.
            ClientWindow::Bits(bits) => bits.min(offered_client),
            // Unanswered means unconstrained by the server, so this side holds
            // itself to the bound it advertised.
            ClientWindow::Absent => offered_client,
        };

        Ok(Negotiated::new(
            Role::Client,
            params.server_no_context_takeover,
            client_no_context_takeover,
            server_max_window_bits,
            client_max_window_bits,
        ))
    }
}

fn render_offer(config: ClientConfig) -> HeaderValue {
    let server_bits = match config.offered_server_max_window_bits() {
        MAX_WINDOW_BITS => None,
        bits => Some(bits),
    };
    // Always advertise client_max_window_bits, valueless at full width. A server
    // may only bound this side's window if the offer said the parameter is
    // understood, so omitting it would forfeit a legal agreement.
    let client_bits = match config.offered_client_max_window_bits() {
        MAX_WINDOW_BITS => ClientBits::Valueless,
        bits => ClientBits::Bits(bits),
    };
    render(
        config.requires_server_no_context_takeover(),
        config.offers_client_no_context_takeover(),
        server_bits,
        &client_bits,
    )
}

fn contains_deflate(headers: &HeaderMap) -> Result<bool, NegotiationError> {
    for value in headers.get_all(SEC_WEBSOCKET_EXTENSIONS) {
        for element in grammar::elements(value.as_bytes())? {
            if grammar::is_deflate(element)? {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

/// The single `permessage-deflate` selection in a response, if there is one.
fn sole_deflate(headers: &HeaderMap) -> Result<Option<Params>, NegotiationError> {
    let mut selected = None;
    for value in headers.get_all(SEC_WEBSOCKET_EXTENSIONS) {
        for element in grammar::elements(value.as_bytes())? {
            if grammar::is_blank(element) || !grammar::is_deflate(element)? {
                continue;
            }
            if selected.replace(grammar::parse_params(element)?).is_some() {
                return Err(NegotiationError::DuplicateExtension);
            }
        }
    }
    Ok(selected)
}
