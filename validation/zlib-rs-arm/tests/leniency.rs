//! zlib-rs ignores the declared window, so the crate's public decoder accepts a
//! peer that compressed wider than it declared.
//!
//! This is the paired arm: it records the leniency deliberately rather than
//! leaving it as an untested assumption, and it is what makes the C arm's
//! rejections attributable to the backend instead of to the payload.

// Each arm uses the subset of the shared scenarios its backend can assert.
#![allow(dead_code)]

include!("../../shared/scenarios.rs");

/// Presence of the far match, so the acceptances below are not vacuous.
#[test]
fn the_payload_really_contains_a_far_reference() {
    for gap in [30_000, 8_000, 5_000, 4_096] {
        let saving = far_match_saving(gap);
        assert!(saving > 3_000, "gap {gap}: a 4 KiB match must show as wire, saw {saving} B");
    }
}

#[test]
fn every_scenario_decodes_whatever_the_declared_window_was() {
    assert_eq!(fresh(15, 30_000), Outcome::Exact, "the conforming control");
    assert_eq!(fresh(9, 30_000), Outcome::Exact, "declared 9, compressed at 15");
    assert_eq!(after_no_context_reinit(9, 30_000), Outcome::Exact);
    assert_eq!(after_bfinal_reinit(9, 30_000), Outcome::Exact);
    for (declared, gap) in [(11, 4_096), (12, 4_096), (12, 5_000), (13, 5_000)] {
        assert_eq!(fresh(declared, gap), Outcome::Exact, "declared {declared}, gap {gap}");
    }
}

/// The backend premise the crate's `stream_open` widening classification rests
/// on, measured on this arm's backend. Both arms run it: it is `flate2`'s
/// contract rather than a difference between the two, so a divergence in it is
/// the finding.
#[test]
fn a_stream_start_cannot_produce_before_it_consumes() {
    assert_eq!(stream_starts_that_broke_the_premise(), Vec::<String>::new());
}
