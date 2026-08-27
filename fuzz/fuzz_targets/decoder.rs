//! `Decoder::decompress` over arbitrary fragment sequences and ceilings.
//!
//! `DecompressedLimit` is a decompression-bomb guard, which makes it the one
//! surface here where an adversarial generator is worth more than a test.
//!
//! The fragment records come from `ws_pmd_fuzz::fragments`, which documents the
//! format and why it is written out rather than derived. `tests/corpus.rs`
//! pins what each named seed decodes to.
//!
//! Two contracts are asserted rather than merely exercised, because a decoder
//! that silently breaks either still returns `Ok`:
//!
//! * the cumulative output of a message never exceeds the ceiling supplied on
//!   the call that produced it, and
//! * the first error poisons the decoder, so every later call fails.

#![no_main]

use libfuzzer_sys::fuzz_target;
use ws_pmd::{CodecError, DecompressedLimit};
use ws_pmd_fuzz::{client_decoder, fragments};

fuzz_target!(|data: &[u8]| {
    let mut decoder = client_decoder();

    // Mirrors the decoder's own accounting: a non-final fragment adds to the
    // message in progress, a final one ends it.
    let mut delivered = 0usize;
    let mut poisoned = false;

    for fragment in fragments(data) {
        let limit = fragment.limit;
        let result = decoder.decompress(
            fragment.bytes,
            fragment.final_fragment,
            DecompressedLimit::bytes(limit),
        );

        if poisoned {
            assert!(
                matches!(result, Err(CodecError::Poisoned)),
                "a poisoned decoder accepted another fragment"
            );
            continue;
        }

        match result {
            Ok(output) => {
                let total = delivered.saturating_add(output.len());
                assert!(total <= limit, "message reached {total} bytes past a ceiling of {limit}");
                delivered = if fragment.final_fragment { 0 } else { total };
            }
            Err(_) => poisoned = true,
        }
    }
});
