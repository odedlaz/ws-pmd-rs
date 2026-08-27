# Contributing to ws-pmd-rs

Thank you for wanting to help. This crate has a deliberately narrow job, and the sections
below describe what belongs in it and what a change has to pass before it lands.

The repository is `odedlaz/ws-pmd-rs`; the crate it publishes is `ws-pmd`.

## Scope

Version 0.1 is an RFC 7692 correctness component. It is **not** a general WebSocket
extension framework and **not** a compression-performance project. The public API is the
smallest surface that serves its target integrations, and it stays that way until those
integrations have shipped and produced real usage feedback.

In scope:

- Conformance bugs against RFC 7692 or the RFC 6455 §9.1 header grammar.
- Negotiation edge cases: parameter arity, window bounds, takeover, repeated header fields,
  malformed input, and the boundary between declining and failing a handshake.
- Codec correctness: trailer handling, stream and fragment boundaries, context takeover,
  the decompressed-byte ceiling, and poisoning.
- Portability across the `flate2` backends, including anything the two do not agree on.
- Documentation that makes an existing guarantee easier to use correctly.

Out of scope, and better raised as an issue than as a pull request:

- Framing, masking, fragmentation, close behaviour, UTF-8 validation, or message assembly.
  These belong to the host, and moving one here would change what the crate is.
- Other WebSocket extensions, or a registry for composing them.
- Runtime, I/O, or async integration of any kind.
- Performance tuning without a named consumer and a measurement (see
  [Measurements](#measurements)).

New public API needs a named consumer that requires it. Breaking changes need a
minor-version bump and evidence from the consumer adapters.

## Reporting a bug

Open an issue on the repository.

A useful report names the RFC section or the API contract you believe was violated, the
headers or byte sequence that reproduce it, and which `flate2` backend the graph resolved —
`cargo tree -e features` shows it, and behaviour alone does not.

## Development

You need Rust 1.85 or newer; that is the minimum this crate supports, and raising it is a
breaking change.

[`.github/workflows/ci.yml`](https://github.com/odedlaz/ws-pmd-rs/blob/main/.github/workflows/ci.yml)
is the gate, and the only exhaustive statement of it: the commands, the flags, the feature
and backend matrices, the tool versions, and what `ci-passed` requires. Running it needs a
clone, because it reaches `validation/` and `fuzz/` and neither is in the published package.

Compression-backend behaviour cannot be asserted by the crate's own suite, which is
backend-independent by design. Two named arms cover it, plus a matrix that consumes the
*packaged* crate from outside. Read [`validation/README.md`](validation/README.md) before
changing anything under `validation/`: it owns those commands and the properties they rest
on, including why the two arms must run separately.

## Tests

Every behavioural change comes with a test that fails before it and passes after. State
which one in the commit message.

Three conventions in this suite are deliberate, and a change that quietly undoes one is
worse than no test at all:

- **The decoder is driven by a `flate2` peer, never by this crate's own encoder.** A mistake
  shared by both sides would otherwise pass as a successful round trip. That peer is
  independent of our codec logic, not of DEFLATE — it is the same engine the crate calls.
- **The dev-dependency on `flate2` names no backend.** Asking for one there would satisfy
  `flate2` whatever the crate's own feature table forwards, so a broken forward would still
  build and every test would still pass — the suite would be proving the dev-dependency's
  request rather than the crate's public feature surface.
- **Production code may not panic, index, or exit out of band.** Where a site would, it
  carries an allowance at the site with the invariant named and a test pinning it, so the
  allowance goes red if the invariant stops holding. Add the test with the allowance, not
  after it.

`cargo test` also runs the documentation examples, including the `compile_fail` rows that
pin what the API must refuse to compile.

## Measurements

Any claim about size, speed, or memory must name the **backend, the compression level, and
the platform** it was measured on. The two backends implement one specification and agree
on semantics; they do not agree on bytes, and an unqualified number is wrong in a way no
later reader can detect. This applies to commit messages, pull request bodies, and
documentation alike.

The same rule applies to conformance: this crate is tested against RFC 7692 byte vectors,
which is not the same claim as passing a published conformance suite. Say the first, not
the second.

## Commits

Subjects follow `<type>: <subject>`, where type is `feat`, `fix`, `test`, or `docs`. Keep
the subject lowercase and imperative, and describe the effect rather than the files touched.
Wrap the body near 80 columns.

Use the body for what the diff cannot show: the reason, the tradeoff, the constraint, and
the test that pins it. A change that corrects an earlier mistake should say what was wrong
and why it went unnoticed.

Sign off every commit. `git commit -s` adds the line, and it certifies that you wrote the
patch or otherwise have the right to submit it under this project's license:

```text
Signed-off-by: Your Name <you@example.com>
```

## Pull requests

Keep a pull request to one coherent change that a reviewer can hold in their head at once.
Split anything larger along its own seams, not at an arbitrary line count, and never by
dropping the tests or documentation that make the change reviewable.

The description opens with what changed and why, then adds only what the diff cannot supply:
tradeoffs, compatibility concerns, and anything you checked by hand. Name the gate commands
you ran and any that failed. Reference a related issue in prose rather than with a `Closes`
or `Fixes` trailer.

Rebase rather than merge when the base moves, and keep the branch's commits individually
green — each one should pass the gate on its own.

## License

MIT. See [LICENSE](LICENSE). Contributions are accepted under the same license; your
`Signed-off-by` line is how you state that you may submit them.
