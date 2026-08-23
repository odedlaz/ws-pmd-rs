//! C zlib enforces the negotiated window, so the crate's public decoder rejects
//! a peer that compressed wider than it declared.
//!
//! Expected results here are backend-specific by design. This arm names its
//! backend in its own manifest, so nothing inverts inside it: if feature
//! unification failed to select C zlib, every rejection below fails loudly
//! rather than passing for the wrong reason.

// Each arm uses the subset of the shared scenarios its backend can assert.
#![allow(dead_code)]

include!("../../shared/scenarios.rs");

/// Presence of the far match, before any conclusion rests on its absence.
#[test]
fn the_payload_really_contains_a_far_reference() {
    for gap in [30_000, 8_000, 5_000, 4_096] {
        let saving = far_match_saving(gap);
        assert!(saving > 3_000, "gap {gap}: a 4 KiB match must show as wire, saw {saving} B");
    }
}

/// The known-positive control on the discriminating property: the same stream,
/// at a window wide enough to hold the reference, decodes byte-exact.
#[test]
fn the_same_stream_decodes_at_the_width_that_admits_it() {
    assert_eq!(fresh(15, 30_000), Outcome::Exact);
}

#[test]
fn a_fresh_decoder_rejects_a_reference_past_its_negotiated_window() {
    assert_eq!(fresh(9, 30_000), Outcome::Rejected(CodecError::InvalidStream));
}

/// Both reinitialisation sites, which is where a swapped route or a default
/// reset would re-widen the inflater and start accepting what it must reject.
#[test]
fn the_no_context_reinitialisation_keeps_the_negotiated_window() {
    assert_eq!(after_no_context_reinit(9, 30_000), Outcome::Rejected(CodecError::InvalidStream));
}

#[test]
fn the_bfinal_recovery_keeps_the_negotiated_window() {
    assert_eq!(after_bfinal_reinit(9, 30_000), Outcome::Rejected(CodecError::InvalidStream));
}

/// The boundary tracks the arithmetic rather than merely being crossed. One gap
/// crossing once is consistent with any distance in a factor-of-two band, so the
/// admit threshold has to move with the gap: 4,096 needs 2^12 and 5,000 needs
/// 2^13, and each is rejected one bit below.
#[test]
fn the_rejection_boundary_follows_the_declared_width() {
    let rejected = Outcome::Rejected(CodecError::InvalidStream);
    assert_eq!(fresh(11, 4_096), rejected, "2048 cannot reach 4096");
    assert_eq!(fresh(12, 4_096), Outcome::Exact, "4096 clears 4096");
    assert_eq!(fresh(12, 5_000), rejected, "4096 cannot reach 5000");
    assert_eq!(fresh(13, 5_000), Outcome::Exact, "8192 clears 5000");
}
