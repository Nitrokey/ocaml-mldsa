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

/* Native backends.
 *
 * mldsa-native selects its backends at preprocessing time from the target
 * compiler's predefined macros (src/sys.h): __aarch64__ -> Neon arithmetic +
 * Neon/scalar Keccak; __x86_64__ && __AVX2__ -> AVX2 arithmetic + 4-way AVX2
 * Keccak.  On any other target (or on x86-64 compiled without -mavx2) the
 * *_BACKEND_FILE headers define nothing and the portable C code is used, so it
 * is safe to enable the backends unconditionally.  The matching assembly is
 * in mldsa_native_asm.S, built by a dune rule into libmldsa_asm.a.
 *
 * There is no runtime CPU detection: the default mld_sys_check_capability()
 * returns 1, i.e. "whatever was enabled at compile time is present".  This
 * is intentional -- the deployment CPU is known at build time (x86-64 with
 * AVX2, or a Raspberry Pi 5 / Cortex-A76).  If that ever changes, define
 * MLD_CONFIG_CUSTOM_CAPABILITY_FUNC (see upstream config) or build with
 * -DMLDSA_OCAML_NO_NATIVE.
 */
#if !defined(MLDSA_OCAML_NO_NATIVE)
#define MLD_CONFIG_USE_NATIVE_BACKEND_ARITH
#define MLD_CONFIG_USE_NATIVE_BACKEND_FIPS202
#define MLD_CONFIG_ARITH_BACKEND_FILE "native/meta.h"
#define MLD_CONFIG_FIPS202_BACKEND_FILE "fips202/native/auto.h"
#endif

/* Optional: -DMLDSA_OCAML_REDUCE_RAM trades speed for a much smaller stack
 * footprint (ML-DSA-87 signing: ~107 KB -> ~14 KB). Useful for targets with a
 * small C stack; off by default. */
#if defined(MLDSA_OCAML_REDUCE_RAM)
#define MLD_CONFIG_REDUCE_RAM
#endif

/* Default namespace fallback required by upstream headers. */
#define MLD_DEFAULT_NAMESPACE_PREFIX PQCP_MLDSA_NATIVE_MLDSA

#endif /* MLD_CONFIG_H */
