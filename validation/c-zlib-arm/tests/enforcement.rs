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
    for gap in [30_000, 8_000] {
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
    assert_eq!(fresh(9, 30_000), Outcome::Rejected);
}

/// Both reinitialisation sites, which is where a swapped route or a default
/// reset would re-widen the inflater and start accepting what it must reject.
#[test]
fn the_no_context_reinitialisation_keeps_the_negotiated_window() {
    assert_eq!(after_no_context_reinit(9, 30_000), Outcome::Rejected);
}

#[test]
fn the_bfinal_recovery_keeps_the_negotiated_window() {
    assert_eq!(after_bfinal_reinit(9, 30_000), Outcome::Rejected);
}

/// The boundary tracks the arithmetic rather than merely being crossed: a
/// 2,000-byte gap needs 2^11 to reach, so 9 and 10 reject and 12 admits it.
#[test]
fn the_rejection_boundary_follows_the_declared_width() {
    assert_eq!(fresh(9, 2_000), Outcome::Rejected, "512 cannot reach 2000");
    assert_eq!(fresh(10, 2_000), Outcome::Rejected, "1024 cannot reach 2000");
    assert_eq!(fresh(12, 2_000), Outcome::Exact, "4096 clears 2000");
}
