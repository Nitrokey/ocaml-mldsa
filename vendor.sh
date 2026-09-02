#!/bin/sh
# Re-vendor the mldsa-native C sources into src/native/mldsa_native/.
#
# Usage: ./vendor.sh [git-ref]        (default: the ref recorded in VENDORED)
#
# We copy only the portable C frontend + C FIPS-202 backend. The assembly
# backends (mldsa/src/native, mldsa/src/fips202/native, mldsa_native_asm.S)
# are deliberately left out: this library targets cross-compiled MirageOS
# unikernels, so we want a pure-C, toolchain-agnostic build.
set -eu

UPSTREAM=https://github.com/pq-code-package/mldsa-native.git
REF="${1:-$(sed -n 's/^ref: //p' "$(dirname "$0")/VENDORED" 2>/dev/null || echo main)}"
DEST="$(cd "$(dirname "$0")" && pwd)/src/native/mldsa_native"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
git clone -q "$UPSTREAM" "$TMP/src"
git -C "$TMP/src" checkout -q "$REF"
COMMIT="$(git -C "$TMP/src" rev-parse HEAD)"

rm -rf "$DEST"
mkdir -p "$DEST"
cp -R "$TMP/src/mldsa/." "$DEST/"
rm -rf "$DEST/src/native" "$DEST/src/fips202/native" "$DEST/mldsa_native_asm.S" "$DEST/README.md"
cp "$TMP/src/LICENSE" "$DEST/LICENSE"

cat > "$(dirname "$0")/VENDORED" <<EOT
upstream: $UPSTREAM
ref: $REF
commit: $COMMIT
date: $(date -u +%Y-%m-%d)
EOT
echo "Vendored mldsa-native $COMMIT into $DEST"
