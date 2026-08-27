//! Reports which behaviour answers, never which backend. See `run.sh`: the two
//! coincide only at the locked flate2, and provenance is a graph fact.
#![allow(dead_code)]
include!("shared/scenarios.rs");

#[test]
fn which_behaviour_answers() {
    // The control first: at a width that admits the reference, every backend
    // decodes it. If this fails the payload is wrong and the row below is void.
    assert_eq!(fresh(15, 30_000), Outcome::Exact, "control failed; the rig is wrong");

    let behaviour = match fresh(9, 30_000) {
        Outcome::Exact => "lenient",
        Outcome::Rejected(CodecError::InvalidStream) => "enforces",
        other => panic!("neither known behaviour: {other:?}"),
    };
    println!("BEHAVIOUR={behaviour}");
}
