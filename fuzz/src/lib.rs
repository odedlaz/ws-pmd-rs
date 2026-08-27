//! Input decoding shared by the fuzz targets and by the corpus test.
//!
//! The `decoder` target needs a fragment sequence rather than a flat byte
//! string. It used to get one from an `Arbitrary`-derived struct, which encoded
//! the sequence in `arbitrary`'s internal wire format -- a continuation `bool`
//! ahead of every `Vec` element, `bool` read as `byte & 1`. That format is not
//! a stable interface, and every seed in `corpus/decoder/` had been written as
//! though its first bytes were compressed payload: five parsed as zero
//! fragments and the sixth as one empty one, so the target reported clean over
//! an input set that never called the decoder. An explicit format cannot drift
//! that way on a dependency bump, and a person can read and write a seed.

use http::{header::SEC_WEBSOCKET_EXTENSIONS, HeaderMap, HeaderValue};
use ws_pmd::{ClientConfig, ClientOffer, Decoder, EncoderConfig, PmdComposition};

/// The plan's ceiling on generated limits: high enough that an ordinary message
/// is not clipped, low enough that a bomb stays bounded inside the run.
pub const MAX_LIMIT: usize = 1 << 20;

/// Bytes of header per record: flags, then the ceiling, then the payload length.
const HEADER: usize = 6;

/// One fragment, borrowed from the input rather than copied out of it.
#[derive(Debug, PartialEq, Eq)]
pub struct Fragment<'a> {
    pub bytes: &'a [u8],
    pub final_fragment: bool,
    pub limit: usize,
}

/// Splits an input into fragment records.
///
/// ```text
/// byte 0      flags; bit 0 set means this fragment ends the message
/// bytes 1..4  ceiling, big-endian u24, taken modulo MAX_LIMIT + 1
/// bytes 4..6  payload length, big-endian u16
/// bytes 6..   payload
/// ```
///
/// A record needs its whole header, so a shorter tail ends the sequence. A
/// declared length longer than what the input holds is **clamped, not
/// rejected**: that is the property the previous format lacked, and it is why
/// truncating a seed used to collapse it to zero fragments instead of one short
/// one. The `u16` length field is also what bounds a single fragment, at 65,535
/// bytes -- the 64 KiB ceiling the old `MAX_FRAGMENT` constant expressed, now
/// enforced by the format instead of by a clamp the input could not reach.
#[must_use]
pub fn fragments(data: &[u8]) -> Vec<Fragment<'_>> {
    let mut rest = data;
    let mut out = Vec::new();
    while rest.len() >= HEADER {
        let (header, body) = rest.split_at(HEADER);
        let limit = ((usize::from(header[1]) << 16)
            | (usize::from(header[2]) << 8)
            | usize::from(header[3]))
            % (MAX_LIMIT + 1);
        let declared = usize::from(u16::from_be_bytes([header[4], header[5]]));
        let (bytes, tail) = body.split_at(declared.min(body.len()));
        out.push(Fragment { bytes, final_fragment: header[0] & 1 == 1, limit });
        rest = tail;
    }
    out
}

/// A decoder built through a real client handshake, so the agreement under test
/// is one negotiation produced rather than one synthesised.
///
/// Shared with the corpus test: asserting that a seed reaches its advertised
/// state means decoding it, and a binary cannot be imported.
///
/// # Panics
///
/// If any step of that handshake fails. None of them reads the fuzzer's input,
/// so a failure is a regression rather than a finding, and each panic names its
/// step. Returning `None` instead let the `decoder` target return before its
/// first `decompress` call for every input and still report green.
#[must_use]
pub fn client_decoder() -> Decoder {
    let mut request = HeaderMap::new();
    let offer = ClientOffer::install(ClientConfig::new(), &mut request)
        .expect("the default offer installs into an empty request");
    let mut response = HeaderMap::new();
    response.append(SEC_WEBSOCKET_EXTENSIONS, HeaderValue::from_static("permessage-deflate"));
    offer
        .seal(&request)
        .expect("the sealed offer matches the request it wrote")
        .finish(&response, PmdComposition::Compatible)
        .expect("a bare `permessage-deflate` response is acceptable")
        .expect("an accepted response yields an agreement")
        .into_codecs(EncoderConfig::new())
        .1
}

#[cfg(test)]
mod tests {
    use super::fragments;

    #[test]
    fn an_over_declared_length_is_clamped_not_rejected() {
        // Declares 0xffff payload bytes and supplies three. The old format dropped
        // the fragment entirely in this situation; this one delivers a short one.
        let data = [0x01, 0x00, 0x00, 0x10, 0xff, 0xff, 0xaa, 0xbb, 0xcc];
        let parsed = fragments(&data);
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].bytes, &[0xaa, 0xbb, 0xcc]);
        assert!(parsed[0].final_fragment);
        assert_eq!(parsed[0].limit, 0x0010);
    }

    #[test]
    fn a_truncated_record_ends_the_sequence() {
        // One whole record, then five bytes -- one short of a header.
        let mut data = vec![0x00, 0x00, 0x00, 0x01, 0x00, 0x02, 0x41, 0x42];
        data.extend_from_slice(&[0x01, 0x00, 0x00, 0x01, 0x00]);
        let parsed = fragments(&data);
        assert_eq!(parsed.len(), 1, "the short tail must not become a record");
        assert_eq!(parsed[0].bytes, b"AB");
        assert!(!parsed[0].final_fragment);
    }

    #[test]
    fn an_input_shorter_than_one_header_yields_no_fragments() {
        for len in 0..6 {
            assert!(fragments(&vec![0xff; len]).is_empty(), "{len} bytes should parse to nothing");
        }
    }
}
