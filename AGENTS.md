# AGENTS.md

Guidance for agents working in this repository. [CONTRIBUTING.md](CONTRIBUTING.md) is
canonical for scope, review process, and anything not covered here.

## What this crate is

RFC 7692 `permessage-deflate`: negotiation and per-connection DEFLATE state, independent of
any WebSocket implementation. It has no socket, no runtime, and no frame type.

Framing, fragmentation, masking, message assembly, control frames, close codes, and UTF-8
validation belong to the host. A change that pulls one of them in here is out of scope even
when it makes a caller simpler — say so and stop, rather than implementing it.

## The gate

Run all of this locally before you claim a change is green. CI is authoritative.

```sh
cargo fmt --check
cargo clippy --locked
cargo clippy --locked --all-targets
cargo clippy --locked --all-features
cargo test --locked --no-fail-fast
```

The three clippy runs widen over different axes — default production code, targets,
features — and none subsumes another. `--no-fail-fast` keeps a failing binary from hiding
the ones after it.

Backend-dependent behaviour is not in that suite, which is backend-independent by design:

```sh
cargo test --manifest-path validation/zlib-rs-arm/Cargo.toml
cargo test --manifest-path validation/c-zlib-arm/Cargo.toml
./validation/consumer-matrix/run.sh
```

**Run the two arms separately.** Cargo features are additive and unify per build, so
building them together gives both arms the C backend, and the zlib-rs arm stops testing
what it is named for. Read `validation/README.md` before editing anything under
`validation/`; the fixture properties it describes are load-bearing.

`validation/` is excluded from the published package, and the consumer matrix builds the
*packaged* crate rather than this worktree — a path dependency would test files the package
does not ship.

## Conventions the tools do not enforce

- **Do not add nightly-only options to `rustfmt.toml`.** A published crate formats on
  stable. `clippy.toml`'s one `disallowed-methods` entry carries its own reason; read it
  there rather than working around the lint.
- **Production code may not panic, index, or exit out of band.** Where a site would, add
  the allowance *and* the test pinning the invariant in the same change, so the allowance
  goes red if the invariant stops holding.
- **The decoder's tests drive it from a `flate2` peer, never from this crate's own
  encoder,** and the `flate2` dev-dependency names no backend on purpose. Both look like
  tidy-ups waiting to happen. Undoing either makes the suite prove the test's own setup
  instead of the crate.
- **Keep the reason with the code.** Module and item docs here carry the constraint that
  produced the shape. Preserve that when you edit around them, and update it when the
  reason changes.
- **A claim here lives in several files at once.** What the test peers are independent of
  sat in `Cargo.toml`, `src/`, `tests/` and all three docs — six sites for one sentence.
  When you correct one, grep the stem tree-wide and write down the sense of **every** hit:
  an unclassified hit reads exactly like an absent one, and the sweep's own output then
  becomes the evidence it was checked. Then fix each site on its own terms. A qualification
  that is load-bearing at one site is a false claim at a site that never rested on it.

## Claims you may not make

This crate is deployed nowhere. Do not write, in code, docs, commits, or pull requests:

- Performance, overhead, ratio, or memory numbers without naming the **backend, the
  compression level, and the platform**. The two backends agree on semantics and never on
  bytes, so an unqualified number is wrong in a way no later reader can detect.
- "Conformant", or any reference to a conformance suite. The true statement is that the
  crate is tested against RFC 7692 byte vectors.
- "Production-ready", "battle-tested", or any claim of deployment or adoption.
- Integrations that do not exist. No adapter ships today.
- That `zlib-rs` and `zlib` are mutually exclusive. They are activation requests; Cargo
  unions features across a graph, so selecting one cannot stop a dependent enabling the
  other.

If you want to state something and cannot find the evidence, leave it out and say what you
wanted to state.

## Commits and branches

Work on a branch; do not commit to `main`. One coherent change per commit, each green on
its own.

Subjects are `<type>: <subject>` — `feat`, `fix`, `test`, `docs` — lowercase, imperative,
describing the effect rather than the files. Wrap bodies near 80 columns and use them for
the reason, the tradeoff, and the test that pins the change.

Every commit carries `Co-authored-by:` and `Signed-off-by:` naming the accountable human.

## Environment

Rust 1.85 is the minimum this crate supports; raising it is a breaking change. Dependencies
are `http`, `thiserror`, and `flate2`, and adding a fourth needs a reason in the pull
request.
