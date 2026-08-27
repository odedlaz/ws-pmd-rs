//! Every named seed reaches the state its name advertises, and the record
//! parser behaves at its edges.
//!
//! The previous corpus did neither. Encoded in `arbitrary`'s internal wire
//! format, five of the six seeds parsed as zero fragments and the sixth as one
//! empty one, so the `decoder` target ran to green over an input set that never
//! called the decoder. These assertions make that failure loud rather than
//! invisible.
//!
//! The parser's own mechanics are covered beside the parser, in `src/lib.rs`: a
//! hand-written format sits between libFuzzer and the crate, so a bug in it
//! would distort the explored input space exactly as quietly as the corpus did.

use ws_pmd::{CodecError, DecompressedLimit};
use ws_pmd_fuzz::{client_decoder, fragments, MAX_LIMIT};

/// The outcome a seed is named for. Recorded because a seed whose outcome
/// nobody pinned is a seed nobody can tell has stopped reaching its state.
enum Outcome {
    /// Every call returns `Ok` and their outputs concatenate to this.
    Decodes(&'static [u8]),
    /// The stream is refused. Which error is not the point here; that a
    /// defined answer comes back rather than a panic or a hang is.
    Refused,
    /// The decompression-bomb guard fires. This one names its variant, because
    /// the guard is the entire reason the seed exists.
    OverCeiling,
}

struct Expected {
    name: &'static str,
    /// `(payload, final_fragment, limit)` per record, in order.
    records: &'static [(&'static [u8], bool, usize)],
    outcome: Outcome,
}

/// Raw-deflate of `Hello`, split various ways. Verified by inflating each
/// payload independently of this crate before the seeds were written.
const HELLO: &[u8] = &[0xf2, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x00];
const HELLO_BFINAL: &[u8] = &[0xf3, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x00, 0x00];

const SEEDS: &[Expected] = &[
    Expected {
        name: "hello",
        records: &[(HELLO, true, MAX_LIMIT)],
        outcome: Outcome::Decodes(b"Hello"),
    },
    Expected {
        name: "hello-bfinal",
        records: &[(HELLO_BFINAL, true, MAX_LIMIT)],
        outcome: Outcome::Decodes(b"Hello"),
    },
    Expected {
        name: "split",
        records: &[
            (&[0xf2, 0x48, 0xcd], false, MAX_LIMIT),
            (&[0xc9, 0xc9, 0x07, 0x00], true, MAX_LIMIT),
        ],
        outcome: Outcome::Decodes(b"Hello"),
    },
    Expected {
        name: "sync-flush",
        records: &[
            (&[0xf2, 0x48, 0x05, 0x00, 0x00, 0x00, 0xff, 0xff], false, MAX_LIMIT),
            (&[0xca, 0xc9, 0xc9, 0x07, 0x00], true, MAX_LIMIT),
        ],
        outcome: Outcome::Decodes(b"Hello"),
    },
    Expected { name: "empty-final", records: &[(&[], true, MAX_LIMIT)], outcome: Outcome::Refused },
    Expected { name: "zero-limit", records: &[(HELLO, true, 0)], outcome: Outcome::OverCeiling },
];

const CORPUS: &str = "corpus/decoder";

fn corpus_dir() -> String {
    format!("{}/{CORPUS}", env!("CARGO_MANIFEST_DIR"))
}

/// The seeds the repository carries, asked of git rather than of the directory.
///
/// `cargo fuzz run` writes its discoveries into this folder, so reading the
/// directory turned the assertion below red after any local fuzzing session --
/// during the workflow it exists to support. CI's population is this one either
/// way: a runner checks out tracked files and nothing else.
///
/// Every failure panics rather than returning an empty vector. An empty
/// population satisfies a set comparison against an empty table, which is the
/// instrument-that-examines-nothing this file exists to catch.
fn tracked_seeds() -> Vec<String> {
    let output = std::process::Command::new("git")
        .args(["-C", env!("CARGO_MANIFEST_DIR"), "ls-files", "-z", "--", CORPUS])
        .output()
        .expect("git ls-files runs");
    assert!(
        output.status.success(),
        "git ls-files failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let listing = std::str::from_utf8(&output.stdout).expect("git ls-files emits utf-8 paths");
    let prefix = format!("{CORPUS}/");
    let mut names: Vec<String> = listing
        .split('\0')
        .filter(|path| !path.is_empty())
        .map(|path| {
            path.strip_prefix(&prefix)
                .filter(|name| !name.contains('/'))
                .unwrap_or_else(|| panic!("unexpected path under {CORPUS}: {path}"))
                .to_owned()
        })
        .collect();
    assert!(!names.is_empty(), "git reports no tracked seed under {CORPUS}");
    names.sort();
    names
}

fn seed(name: &str) -> Vec<u8> {
    let path = format!("{}/{name}", corpus_dir());
    std::fs::read(&path).unwrap_or_else(|e| panic!("corpus seed {path}: {e}"))
}

/// Enumerated from the repository rather than from `SEEDS`, so a seed committed
/// later cannot sit in the corpus with nothing asserting it.
#[test]
fn every_corpus_seed_has_an_expectation() {
    let mut expected: Vec<String> = SEEDS.iter().map(|s| s.name.to_owned()).collect();
    expected.sort();
    assert_eq!(tracked_seeds(), expected, "the corpus and the expectation table disagree");
}

#[test]
fn every_seed_parses_to_its_advertised_records() {
    for expected in SEEDS {
        let data = seed(expected.name);
        let parsed = fragments(&data);
        assert_eq!(parsed.len(), expected.records.len(), "{}: record count", expected.name);
        for (i, (record, want)) in parsed.iter().zip(expected.records).enumerate() {
            let (bytes, final_fragment, limit) = *want;
            assert_eq!(record.bytes, bytes, "{}: record {i} payload", expected.name);
            assert_eq!(
                record.final_fragment, final_fragment,
                "{}: record {i} final flag",
                expected.name
            );
            assert_eq!(record.limit, limit, "{}: record {i} limit", expected.name);
        }
    }
}

#[test]
fn every_seed_reaches_the_state_it_is_named_for() {
    for expected in SEEDS {
        let data = seed(expected.name);
        let parsed = fragments(&data);
        let mut decoder = client_decoder();
        let mut output = Vec::new();
        let mut error = None;
        for record in &parsed {
            match decoder.decompress(
                record.bytes,
                record.final_fragment,
                DecompressedLimit::bytes(record.limit),
            ) {
                Ok(chunk) => output.extend_from_slice(chunk.as_ref()),
                Err(e) => {
                    error = Some(e);
                    break;
                }
            }
        }
        match expected.outcome {
            Outcome::Decodes(want) => {
                assert!(error.is_none(), "{}: expected to decode, got {error:?}", expected.name);
                assert_eq!(output, want, "{}: decoded bytes", expected.name);
            }
            Outcome::Refused => {
                assert!(error.is_some(), "{}: expected the stream to be refused", expected.name);
            }
            Outcome::OverCeiling => {
                assert!(
                    matches!(error, Some(CodecError::MessageTooLong { .. })),
                    "{}: expected the ceiling to fire, got {error:?}",
                    expected.name
                );
            }
        }
    }
}
