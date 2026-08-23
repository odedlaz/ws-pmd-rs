# Named backend arms

`c-route-oracle`. The crate's canonical gate is backend-independent by design, so it
cannot assert anything that depends on which flate2 backend a downstream feature graph
selects. These two arms name their backend in their own manifests and assert opposite
results, so nothing inverts inside either one.

```sh
cargo test --manifest-path validation/zlib-rs-arm/Cargo.toml   # leniency, the pinned backend
cargo test --manifest-path validation/c-zlib-arm/Cargo.toml    # enforcement, C zlib
```

**Run them separately.** Cargo features are additive and unify per build, so building both
arms together gives both the C backend. Each arm carries an empty `[workspace]` table to
keep that from happening by accident. Confirm which backend an arm got with
`cargo tree -e features` — look for `flate2 feature "any_c_zlib"` and `libz-sys`, and never
with `new_with_window_bits(false, 8)`, whose panic is flate2's own frontend assert and
fires identically under every backend.

The arms share one scenario source, `include!`d rather than made a crate, so they cannot
drift and neither can be built with the other's backend.

Both select their backend **through the crate's own feature**, the way a consumer does, and
neither asks flate2 for one directly. Two things follow. Each arm's graph holds exactly one
backend, so nothing has to win a dispatch -- and the dispatch is what inverts below the
lock. And a forward that forwards nothing fails both arms loudly instead of being masked by
their own request: measured, with `zlib-rs = []` and `zlib = []` in the crate manifest, both
arms stop at *"You need to choose a zlib backend"* where both previously stayed green.

## What each arm is for

C zlib sizes its inflater window `1 << wbits` and enforces it while decoding; zlib-rs
takes a full-size window whatever it is told and enforces nothing. So a peer that declares
`server_max_window_bits=9` and compresses at 15 is rejected on one backend and decoded
byte-exact on the other.

**That divergence is a property of the locked flate2, not of the two backends.** At flate2
1.0.31 the `zlib-rs` feature arrives through the `libz-rs-sys 0.2.1` shim and *enforces*
the declared window, so the same probe reports "C" in a graph with no C in it. Two things
differ between the ends of our declared range -- the shim and the zlib-rs version -- and
which of them closes the divergence is unmeasured. The arms are sound because the lock
pins 1.1.9; do not carry the claim to another version without re-running it. The C arm owns production construction and both reinitialisation
paths; the zlib-rs arm records the leniency deliberately, which is what makes the C arm's
rejections attributable to the backend rather than to the payload.

Payload and protocol come from `RESEARCH/PMD_FAR_REFERENCE_REPRODUCER_2026_08_23/`. Its
four properties are load-bearing: unmistakable far-match presence, a self-proving
discriminator, a control positive for the discriminating property, and a boundary that
tracks the arithmetic rather than merely being crossed. Do not weaken any of them.

# Consumer matrix

The arms prove behaviour on a named backend. `consumer-matrix/run.sh` proves the *public
feature surface*: seven graphs, each an external crate consuming the package unpacked from
`cargo package` rather than this worktree, so it cannot pass on files the package excludes.

```sh
./validation/consumer-matrix/run.sh
```

It reports two columns and keeps them apart. **Provenance** -- which backend crate is
compiled -- is what a consumer choosing `zlib-rs` is actually choosing, and it is visible
only in the graph. **Behaviour** is what the arms pin. One probe cannot serve both:
`libz-sys` and `zlib-rs` implement one specification, so a behavioural backend oracle is a
bet on a divergence, and it stops discriminating wherever the two agree.

The floor row is provenance-only for that reason, not as a fallback. The same
default-plus-external-C graph binds C at flate2 1.1.9 and the Rust backend at 1.0.31, and
no behaviour separates them there.
