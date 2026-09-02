/*
 * mldsa-native configuration for the OCaml bindings.
 *
 * Selected via MLD_CONFIG_FILE (see mldsa_stubs.c). It replaces the upstream
 * mldsa_native_config.h entirely, so every option we rely on is spelled out
 * here.  Upstream documents all options in
 * src/native/mldsa_native/mldsa_native_config.h.
 */
#ifndef MLD_CONFIG_H
#define MLD_CONFIG_H

/* Set per inclusion by mldsa_native_all.c (44 / 65 / 87). */
#ifndef MLD_CONFIG_PARAMETER_SET
#error "MLD_CONFIG_PARAMETER_SET must be defined by the including file"
#endif

/* All three security levels are compiled into one translation unit.
 * Public symbols become <prefix><level>_<name>, e.g. ocaml_mldsa44_verify.
 * The prefix is deliberately unusual so that a unikernel or binary that also
 * links liboqs / another mldsa-native copy does not clash. */
#define MLD_CONFIG_MULTILEVEL_BUILD
#define MLD_CONFIG_NAMESPACE_PREFIX ocaml_mldsa

/* Single-compilation-unit build: nothing needs external linkage except the
 * CAMLprim wrappers in mldsa_stubs.c. */
#define MLD_CONFIG_INTERNAL_API_QUALIFIER static
#define MLD_CONFIG_EXTERNAL_API_QUALIFIER static

/* Randomness always comes from the OCaml side (e.g. Mirage_crypto_rng) and is
 * passed explicitly to the *_internal functions. Consequently the C code has
 * no randombytes() dependency at all, which is exactly what we want for a
 * cross-compiled unikernel. */
#define MLD_CONFIG_NO_RANDOMIZED_API

/* Portable C only. The AArch64/x86_64 assembly backends are not vendored
 * (see vendor.sh); leave these undefined. */
#undef MLD_CONFIG_USE_NATIVE_BACKEND_ARITH
#undef MLD_CONFIG_USE_NATIVE_BACKEND_FIPS202

/* Optional: -DMLDSA_OCAML_REDUCE_RAM trades speed for a much smaller stack
 * footprint (ML-DSA-87 signing: ~107 KB -> ~14 KB). Useful for targets with a
 * small C stack; off by default. */
#if defined(MLDSA_OCAML_REDUCE_RAM)
#define MLD_CONFIG_REDUCE_RAM
#endif

/* Default namespace fallback required by upstream headers. */
#define MLD_DEFAULT_NAMESPACE_PREFIX PQCP_MLDSA_NATIVE_MLDSA

#endif /* MLD_CONFIG_H */
