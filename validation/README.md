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

## What each arm is for

C zlib sizes its inflater window `1 << wbits` and enforces it while decoding; zlib-rs
takes a full-size window whatever it is told and enforces nothing. So a peer that declares
`server_max_window_bits=9` and compresses at 15 is rejected on one backend and decoded
byte-exact on the other. The C arm owns production construction and both reinitialisation
paths; the zlib-rs arm records the leniency deliberately, which is what makes the C arm's
rejections attributable to the backend rather than to the payload.

Payload and protocol come from `RESEARCH/PMD_FAR_REFERENCE_REPRODUCER_2026_08_23/`. Its
four properties are load-bearing: unmistakable far-match presence, a self-proving
discriminator, a control positive for the discriminating property, and a boundary that
tracks the arithmetic rather than merely being crossed. Do not weaken any of them.
