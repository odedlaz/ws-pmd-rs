//! The `Sec-WebSocket-Extensions` grammar, over raw bytes.
//!
//! Header values are parsed as bytes and never decoded to `str`. Isolation from
//! an unrelated extension means this crate does not *interpret* it, not that it
//! accepts bad syntax from it: RFC 6455 section 9.1 puts a MUST on the recipient
//! of any non-conforming value, whichever extension it names, so
//! [`validate`] checks the whole field before anything is selected.

use http::{header::SEC_WEBSOCKET_EXTENSIONS, HeaderMap};

use crate::error::NegotiationError;

/// The extension token this crate implements.
pub const NAME: &str = "permessage-deflate";

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
pub fn elements(value: &[u8]) -> Result<Vec<&[u8]>, NegotiationError> {
    split(value, b',')
}

/// Split one element into its name and its semicolon-separated parameters.
///
/// Unreachable today — every caller comes through [`elements`], whose parts are
/// provably quote-balanced. It propagates anyway: answering "not
/// permessage-deflate" for an unbalanced element manufactures a classification.
fn segments(element: &[u8]) -> Result<Vec<&[u8]>, NegotiationError> {
    split(element, b';')
}

pub fn trim(value: &[u8]) -> &[u8] {
    let start = value.iter().position(|byte| !byte.is_ascii_whitespace()).unwrap_or(value.len());
    let end = value.iter().rposition(|byte| !byte.is_ascii_whitespace()).map_or(start, |i| i + 1);
    value.get(start..end).unwrap_or_default()
}

/// Whether this element names `permessage-deflate`.
///
/// Compared exactly. RFC 6455 defines the term *ASCII case-insensitive* and
/// applies it where it means it -- the `Upgrade` value, the section 4.1 client
/// checks -- and never to `Sec-WebSocket-Extensions` tokens; RFC 7692 contains
/// no case language at all. `Permessage-Deflate` is therefore a conforming
/// extension name that is simply not this one, not a malformed one.
pub fn is_deflate(element: &[u8]) -> Result<bool, NegotiationError> {
    let segments = segments(element)?;
    let name = segments.first().copied().unwrap_or_default();
    Ok(trim(name) == NAME.as_bytes())
}

/// Whether an element is entirely whitespace, which an empty list position
/// produces and which RFC 7230 list rules permit.
pub fn is_blank(element: &[u8]) -> bool {
    trim(element).is_empty()
}

/// Check the whole `Sec-WebSocket-Extensions` field against RFC 6455 section
/// 9.1, before any element is interpreted or selected.
///
/// Every field line and every element in it, including extensions this crate
/// knows nothing about. A conforming element after a malformed one does not
/// rescue the field, and a supportable offer before one does not hide it --
/// which is why this is a pre-pass rather than a check folded into selection.
pub fn validate(headers: &HeaderMap) -> Result<(), NegotiationError> {
    let mut present = false;
    let mut populated = false;
    for value in headers.get_all(SEC_WEBSOCKET_EXTENSIONS) {
        present = true;
        for element in elements(value.as_bytes())? {
            if is_blank(element) {
                continue;
            }
            populated = true;
            validate_element(element)?;
        }
    }
    // `extension-list = 1#extension`. The list rule permits empty positions but
    // not a list made only of them, so a field that is present and contributes
    // no element is malformed rather than equivalent to an absent header.
    if present && !populated {
        return Err(NegotiationError::MalformedHeader);
    }
    Ok(())
}

/// `extension = extension-token *( ";" extension-param )`.
fn validate_element(element: &[u8]) -> Result<(), NegotiationError> {
    let segments = segments(element)?;
    let (name, parameters) = segments.split_first().ok_or(NegotiationError::MalformedHeader)?;
    validate_token(trim(name))?;
    for parameter in parameters {
        let (name, value) = split_parameter(parameter);
        validate_token(trim(name))?;
        if let Some(value) = value {
            // Section 9.1: "the value after quoted-string unescaping MUST
            // conform to the 'token' ABNF". Both spellings reduce to a token.
            validate_token(&unquote(trim(value))?)?;
        }
    }
    Ok(())
}

/// RFC 2616 `token`: `1*<any CHAR except CTLs or separators>`.
fn validate_token(value: &[u8]) -> Result<(), NegotiationError> {
    if value.is_empty() || !value.iter().copied().all(is_tchar) {
        return Err(NegotiationError::MalformedHeader);
    }
    Ok(())
}

/// The separators excluded here are `()<>@,;:\"/[]?={}`, space and horizontal
/// tab; CTLs and any byte above 127 are excluded by the ranges themselves.
const fn is_tchar(byte: u8) -> bool {
    matches!(byte, b'!' | b'#'..=b'\'' | b'*' | b'+' | b'-' | b'.'
        | b'0'..=b'9' | b'A'..=b'Z' | b'^'..=b'z' | b'|' | b'~')
}

/// The valueless form of `client_max_window_bits` is meaningful on its own: in an
/// offer it advertises that the client can honour any width the server picks.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ClientWindow {
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
pub struct Params {
    pub server_no_context_takeover: bool,
    pub client_no_context_takeover: bool,
    pub server_max_window_bits: Option<u8>,
    pub client_max_window_bits: ClientWindow,
}

/// Decode the parameters of an element already known to name `permessage-deflate`.
///
/// Unknown parameters are rejected: this crate implements PMD only, and an
/// extension it does not fully understand cannot be safely agreed to.
pub fn parse_params(element: &[u8]) -> Result<Params, NegotiationError> {
    let segments = segments(element)?;
    // Each parameter is staged in its own `Option`, so "already seen" is the
    // slot being full rather than a parallel bookkeeping flag that can drift
    // out of step with the value it is supposed to describe.
    let mut server_takeover = None;
    let mut client_takeover = None;
    let mut server_window = None;
    let mut client_window = None;

    for segment in segments.iter().skip(1) {
        let (name, value) = split_parameter(segment);

        // Exact, for the same reason the extension name is. An unregistered
        // spelling is an unknown parameter, which declines the alternative.
        match trim(name) {
            b"server_no_context_takeover" => {
                set_once(&mut server_takeover, no_value(value)?)?;
            }
            b"client_no_context_takeover" => {
                set_once(&mut client_takeover, no_value(value)?)?;
            }
            b"server_max_window_bits" => {
                let value = value.ok_or(NegotiationError::ParameterArity)?;
                set_once(&mut server_window, parse_bits(value)?)?;
            }
            b"client_max_window_bits" => {
                let window = match value {
                    Some(value) => ClientWindow::Bits(parse_bits(value)?),
                    None => ClientWindow::Valueless,
                };
                set_once(&mut client_window, window)?;
            }
            _ => return Err(NegotiationError::UnknownParameter),
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
const fn no_value(value: Option<&[u8]>) -> Result<bool, NegotiationError> {
    match value {
        None => Ok(true),
        Some(_) => Err(NegotiationError::ParameterArity),
    }
}

fn split_parameter(segment: &[u8]) -> (&[u8], Option<&[u8]>) {
    segment.iter().position(|byte| *byte == b'=').map_or((segment, None), |index| {
        (segment.get(..index).unwrap_or_default(), segment.get(index + 1..))
    })
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

#[cfg(test)]
#[expect(clippy::expect_used, reason = "a panic is how a test reports")]
mod tests {
    use super::{elements, NegotiationError};

    /// Quote-aware delimiting became unobservable through the public API when
    /// the whole field started being validated: a conforming parameter value
    /// unescapes to a `token`, which admits neither `,` nor `;`, so every input
    /// where the two behaviours disagree is malformed under both of them. A
    /// mutant that ignores quotes entirely survives every driven row. So the
    /// splitter is pinned here instead, the same way `progress` is.
    #[test]
    fn a_delimiter_inside_a_quoted_string_does_not_split_the_list() {
        let parts = elements(br#"x-other; note="a, permessage-deflate", y"#)
            .expect("the quoting is balanced");
        assert_eq!(parts.len(), 2, "only the comma outside the quotes separates elements");
    }

    #[test]
    fn an_escaped_quote_does_not_close_the_string() {
        let error = elements(br#"x-other; note="a\", b"#).expect_err("the string never closes");
        assert_eq!(error, NegotiationError::MalformedHeader);
    }
}
