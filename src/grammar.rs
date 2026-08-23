//! The `Sec-WebSocket-Extensions` grammar, over raw bytes.
//!
//! Header values are parsed as bytes and never decoded to `str` before the
//! extension token has been classified. An unrelated extension may legally carry
//! any byte a `HeaderValue` admits, including non-UTF-8, and must not fail this
//! crate's parse merely by sitting next to `permessage-deflate`.

use crate::error::NegotiationError;

/// The extension token this crate implements.
pub(crate) const NAME: &str = "permessage-deflate";

/// Split on `delimiter`, honouring quoted strings and quoted pairs.
///
/// Strict by decision: an unterminated quoted string or a trailing escape is a
/// grammar error rather than a tail to be interpreted. Until the closing quote
/// arrives there is no way to know which delimiters separate elements, so any
/// answer derived from such a value is a guess.
fn split(value: &[u8], delimiter: u8) -> Result<Vec<&[u8]>, NegotiationError> {
    let mut parts = Vec::new();
    let mut start = 0;
    let mut quoted = false;
    let mut escaped = false;
    for (index, byte) in value.iter().copied().enumerate() {
        if quoted {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                quoted = false;
            }
        } else if byte == b'"' {
            quoted = true;
        } else if byte == delimiter {
            parts.push(value.get(start..index).unwrap_or_default());
            start = index + 1;
        }
    }
    if quoted || escaped {
        return Err(NegotiationError::MalformedHeader);
    }
    parts.push(value.get(start..).unwrap_or_default());
    Ok(parts)
}

/// Split one header line into its comma-separated extension elements.
pub(crate) fn elements(value: &[u8]) -> Result<Vec<&[u8]>, NegotiationError> {
    split(value, b',')
}

/// Split one element into its name and its semicolon-separated parameters.
///
/// The element is already quote-balanced, so this cannot fail.
fn segments(element: &[u8]) -> Vec<&[u8]> {
    split(element, b';').unwrap_or_else(|_| vec![element])
}

pub(crate) fn trim(value: &[u8]) -> &[u8] {
    let start = value.iter().position(|byte| !byte.is_ascii_whitespace()).unwrap_or(value.len());
    let end = value.iter().rposition(|byte| !byte.is_ascii_whitespace()).map_or(start, |i| i + 1);
    value.get(start..end).unwrap_or_default()
}

/// Whether this element names `permessage-deflate`.
///
/// Extension names are HTTP tokens and match case-insensitively.
pub(crate) fn is_deflate(element: &[u8]) -> bool {
    let Some(name) = segments(element).first().copied() else { return false };
    trim(name).eq_ignore_ascii_case(NAME.as_bytes())
}

/// Whether an element is entirely whitespace, which an empty list position
/// produces and which RFC 7230 list rules permit.
pub(crate) fn is_blank(element: &[u8]) -> bool {
    trim(element).is_empty()
}

/// The valueless form of `client_max_window_bits` is meaningful on its own: in an
/// offer it advertises that the client can honour any width the server picks.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) enum ClientWindow {
    #[default]
    Absent,
    Valueless,
    Bits(u8),
}

/// The four RFC 7692 parameters, as they appeared on the wire.
///
/// This is what was written, not what was agreed. Correspondence rules are
/// applied by the client and server handshakes against their own offer.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Params {
    pub(crate) server_no_context_takeover: bool,
    pub(crate) client_no_context_takeover: bool,
    pub(crate) server_max_window_bits: Option<u8>,
    pub(crate) client_max_window_bits: ClientWindow,
}

/// Decode the parameters of an element already known to name `permessage-deflate`.
///
/// Unknown parameters are rejected: this crate implements PMD only, and an
/// extension it does not fully understand cannot be safely agreed to.
pub(crate) fn parse_params(element: &[u8]) -> Result<Params, NegotiationError> {
    let segments = segments(element);
    // Each parameter is staged in its own `Option`, so "already seen" is the
    // slot being full rather than a parallel bookkeeping flag that can drift
    // out of step with the value it is supposed to describe.
    let mut server_takeover = None;
    let mut client_takeover = None;
    let mut server_window = None;
    let mut client_window = None;

    for segment in segments.iter().skip(1) {
        let (name, value) = split_parameter(segment);
        let name = trim(name);

        if name.eq_ignore_ascii_case(b"server_no_context_takeover") {
            set_once(&mut server_takeover, no_value(value)?)?;
        } else if name.eq_ignore_ascii_case(b"client_no_context_takeover") {
            set_once(&mut client_takeover, no_value(value)?)?;
        } else if name.eq_ignore_ascii_case(b"server_max_window_bits") {
            let value = value.ok_or(NegotiationError::ParameterArity)?;
            set_once(&mut server_window, parse_bits(value)?)?;
        } else if name.eq_ignore_ascii_case(b"client_max_window_bits") {
            let window = match value {
                Some(value) => ClientWindow::Bits(parse_bits(value)?),
                None => ClientWindow::Valueless,
            };
            set_once(&mut client_window, window)?;
        } else {
            return Err(NegotiationError::UnknownParameter);
        }
    }

    Ok(Params {
        server_no_context_takeover: server_takeover.unwrap_or(false),
        client_no_context_takeover: client_takeover.unwrap_or(false),
        server_max_window_bits: server_window,
        client_max_window_bits: client_window.unwrap_or_default(),
    })
}

fn set_once<T>(slot: &mut Option<T>, value: T) -> Result<(), NegotiationError> {
    if slot.replace(value).is_some() {
        return Err(NegotiationError::DuplicateParameter);
    }
    Ok(())
}

/// A flag parameter carries no value; `x=` and `x=y` are both arity errors.
fn no_value(value: Option<&[u8]>) -> Result<bool, NegotiationError> {
    match value {
        None => Ok(true),
        Some(_) => Err(NegotiationError::ParameterArity),
    }
}

fn split_parameter(segment: &[u8]) -> (&[u8], Option<&[u8]>) {
    match segment.iter().position(|byte| *byte == b'=') {
        Some(index) => {
            let name = segment.get(..index).unwrap_or_default();
            let value = segment.get(index + 1..).unwrap_or_default();
            (name, Some(value))
        }
        None => (segment, None),
    }
}

/// Window widths are `1*DIGIT` in 8..=15, optionally quoted.
///
/// A leading zero is rejected rather than normalised: `08` and `009` are not the
/// wire forms RFC 7692 defines, and accepting them would let two peers disagree
/// about whether a value was ever sent.
fn parse_bits(value: &[u8]) -> Result<u8, NegotiationError> {
    let value = unquote(trim(value))?;
    let digits = value.as_slice();
    if digits.is_empty() || !digits.iter().all(u8::is_ascii_digit) {
        return Err(NegotiationError::InvalidWindowBits);
    }
    if digits.len() > 1 && digits.first() == Some(&b'0') {
        return Err(NegotiationError::InvalidWindowBits);
    }
    let bits = digits
        .iter()
        .try_fold(0u8, |total, digit| total.checked_mul(10)?.checked_add(digit - b'0'))
        .ok_or(NegotiationError::InvalidWindowBits)?;
    if !(8..=15).contains(&bits) {
        return Err(NegotiationError::InvalidWindowBits);
    }
    Ok(bits)
}

/// Strip one layer of quoting, resolving quoted pairs.
///
/// A bare `"` anywhere in an unquoted value is a grammar error: it can only be
/// the start of a string that the element-level split already proved unbalanced.
fn unquote(value: &[u8]) -> Result<Vec<u8>, NegotiationError> {
    let Some(rest) = value.strip_prefix(b"\"") else {
        if value.contains(&b'"') {
            return Err(NegotiationError::MalformedHeader);
        }
        return Ok(value.to_vec());
    };
    let mut output = Vec::with_capacity(rest.len());
    let mut bytes = rest.iter().copied();
    while let Some(byte) = bytes.next() {
        match byte {
            b'\\' => output.push(bytes.next().ok_or(NegotiationError::MalformedHeader)?),
            b'"' if bytes.next().is_none() => return Ok(output),
            b'"' => return Err(NegotiationError::MalformedHeader),
            byte => output.push(byte),
        }
    }
    Err(NegotiationError::MalformedHeader)
}
