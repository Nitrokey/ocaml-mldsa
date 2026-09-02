#!/bin/sh
# Re-vendor the mldsa-native C sources into src/native/mldsa_native/.
#
# Usage: ./vendor.sh [git-ref]        (default: the ref recorded in VENDORED)
#
# We copy the full mldsa/ tree: C frontend, C FIPS-202 backend, and the
# AArch64 (Neon) / x86-64 (AVX2) assembly backends plus their bundle
# mldsa_native_asm.S. Backend selection happens at preprocessing time from the
# target compiler's predefined macros (see src/native/mldsa_ocaml_config.h).
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
rm -rf "$DEST/README.md"
# Armv8.1-M/Helium backend is experimental upstream and irrelevant for us.
rm -rf "$DEST/src/fips202/native/armv81m"
cp "$TMP/src/LICENSE" "$DEST/LICENSE"

cat > "$(dirname "$0")/VENDORED" <<EOT
upstream: $UPSTREAM
ref: $REF
commit: $COMMIT
date: $(date -u +%Y-%m-%d)
EOT
echo "Vendored mldsa-native $COMMIT into $DEST"
