#!/usr/bin/env bash
# Proves the crate's published feature surface from outside: every graph here
# consumes the *packaged* crate, unpacked from `cargo package`, not this
# worktree. A path dependency would test files the package excludes.
#
# Two columns, deliberately separate. Provenance -- which backend crate is
# compiled -- is what a consumer selecting `zlib-rs` is choosing, and it is
# observable only in the graph. Behaviour is what the arms pin. One probe cannot
# serve both: `libz-sys` and `zlib-rs` implement one specification, so a
# behavioural backend oracle is a bet on a divergence, and the divergence this
# repo uses (window enforcement) closes below flate2 1.1.9.
set -euo pipefail

root=$(cd "$(dirname "$0")/../.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

cargo package --locked --quiet --manifest-path "$root/Cargo.toml"
tar -xzf "$root"/target/package/permessage-deflate-*.crate -C "$work"
pkg=$(echo "$work"/permessage-deflate-*/)
[ -d "$pkg/src" ] || { echo "unpacked package has no src/: $pkg" >&2; exit 1; }

failures=0

# name | our dependency spec | consumer flate2 stanza | expected sys crates | expected behaviour
run_graph() {
    local name=$1 ours=$2 flate2=$3 want_sys=$4 want_behaviour=$5
    local dir="$work/$name"
    mkdir -p "$dir/tests"
    cat > "$dir/Cargo.toml" <<EOF
[package]
name = "$name"
version = "0.0.0"
edition = "2021"
publish = false

[workspace]

[dependencies]
permessage-deflate = { path = "$pkg"${ours} }
http = "1"
$flate2

# The scenario driver builds peer messages with flate2. No backend request, so
# it adds an edge and no feature to the union under test.
[dev-dependencies.flate2]
version = "1.0.31"
default-features = false
EOF
    cp "$root/validation/shared/scenarios.rs" "$dir/tests/scenarios.rs"
    cp "$root/validation/consumer-matrix/probe.rs" "$dir/tests/probe.rs"
    cp "$root/validation/consumer-matrix/public_api.rs" "$dir/tests/public_api.rs"

    # `|| true` on both: an empty `grep` exits 1, and under `pipefail` that would
    # abort the whole run at the assignment -- silently, before this row is named.
    local sys behaviour output api
    sys=$(cd "$dir" && cargo tree 2>/dev/null \
        | grep -oE '(libz-rs-sys|libz-sys|zlib-rs) v[0-9.]+' | cut -d' ' -f1 | sort -u | tr '\n' ' ' || true)
    sys=${sys% }
    output=$(cd "$dir" && cargo test --quiet -- --nocapture 2>&1 || true)
    behaviour=$(printf '%s\n' "$output" | grep -o 'BEHAVIOUR=.*' | cut -d= -f2 || true)
    # Distinct markers, and unanchored: `cargo test`'s progress dots land on the
    # same line as a `println!`, so `^PUBLIC_API=` matches only the first of two.
    # Counting distinct values also means a rerun cannot inflate the total.
    api=$(printf '%s\n' "$output" | grep -o 'PUBLIC_API=[a-z-]*' | sort -u | wc -l | tr -d ' ')

    printf '  %-30s sys=[%-28s] behaviour=%-9s public-api=%s/2\n' \
        "$name" "$sys" "${behaviour:-DID NOT RUN}" "$api"
    if [ "$sys" != "$want_sys" ]; then
        printf '    FAIL provenance: wanted [%s]\n' "$want_sys" >&2
        failures=$((failures + 1))
    fi
    # Both public-API rows must report. A count rather than a presence check,
    # because one marker plus one failure reads the same as a pass otherwise.
    if [ "$api" != "2" ]; then
        printf '    FAIL public API: %s of 2 rows reported -- the published surface does not build this consumer\n' "$api" >&2
        failures=$((failures + 1))
    fi
    if [ -z "$behaviour" ]; then
        # Checked for every row, including the provenance-only one: `cargo tree`
        # resolves whether or not the graph compiles, so without this the row that
        # skips the behaviour comparison would pass a build failure.
        printf '    FAIL: the probe did not run -- this graph does not build\n' >&2
        failures=$((failures + 1))
    elif [ "$want_behaviour" != "unasserted" ] && [ "$behaviour" != "$want_behaviour" ]; then
        printf '    FAIL behaviour: wanted %s\n' "$want_behaviour" >&2
        failures=$((failures + 1))
    fi
}

no_default=', default-features = false'
external_c() { printf '[dependencies.flate2]\nversion = "%s"\ndefault-features = false\nfeatures = ["zlib"]\n' "$1"; }

echo "consumer graphs against the unpacked package:"
run_graph default            ""                                    "" "zlib-rs" lenient
run_graph isolated-zlib-rs   "$no_default, features = [\"zlib-rs\"]" "" "zlib-rs" lenient
run_graph isolated-c-zlib    "$no_default, features = [\"zlib\"]"    "" "libz-sys" enforces
run_graph zero-external-c    "$no_default"            "$(external_c '1.0.31')" "libz-sys" enforces
run_graph all-features       ", features = [\"zlib-rs\", \"zlib\"]"  "" "libz-sys zlib-rs" enforces
run_graph default-external-c ""                       "$(external_c '=1.1.9')" "libz-sys zlib-rs" enforces

# The floor row is provenance-only, and that is not a fallback. flate2 1.0.31
# has no `any_c_zlib`: `ffi/c.rs:406` binds `libz_rs_sys` whenever `zlib-rs` is
# set anywhere in the union, so this same graph resolves to the Rust backend
# while the row above resolves to C. No behavioural probe separates them here --
# at this version the Rust path enforces the declared window too -- and none
# should be expected to, because what a consumer picks with `zlib-rs` is
# provenance, not behaviour.
run_graph default-external-c-floor "" "$(external_c '=1.0.31')" "libz-rs-sys libz-sys zlib-rs" unasserted

if [ "$failures" -ne 0 ]; then
    echo "$failures deviation(s)" >&2
    exit 1
fi
echo "all graphs as expected"
