/*
 * OCaml stubs for mldsa-native (ML-DSA / FIPS 204).
 *
 * This file is the ONLY translation unit of the C part of the library.  It
 * pulls in the vendored mldsa-native sources for all three parameter sets
 * (via mldsa_native_all.c) and wraps the deterministic *_internal API for
 * OCaml.  All mldsa-native symbols are `static`; the only exported symbols
 * are the CAMLprim functions below.
 *
 * Randomness (key-generation seed, per-signature `rnd`) is always supplied by
 * the caller, so no randombytes() is needed in C.  Buffer lengths are checked
 * on the OCaml side; the checks here are a defensive second line and turn
 * into MLD_ERR_INVALID_ARG rather than memory-unsafe behaviour.
 *
 * All stubs are `[@@noalloc]` on the OCaml side: they never allocate, never
 * call back into OCaml, and never release the runtime lock, so passing
 * `String_val`/`Bytes_val` pointers straight through is safe.
 */

#define MLD_CONFIG_FILE "mldsa_ocaml_config.h"
#include "mldsa_native_all.c"

/* Re-import the per-level constants (MLDSA44_BYTES, ...) and the shared
 * MLD_ERR_* / MLD_PREHASH_* / MLD_DOMAIN_SEPARATION_MAX_BYTES macros, which
 * mldsa_native.c #undef's after each inclusion. CONSTANTS_ONLY skips the
 * function prototypes. */
#define MLD_CONFIG_CONSTANTS_ONLY
#define MLD_CONFIG_PARAMETER_SET 44
#include "mldsa_native/mldsa_native.h"
#undef MLD_CONFIG_PARAMETER_SET
#undef MLD_H
#define MLD_CONFIG_PARAMETER_SET 65
#include "mldsa_native/mldsa_native.h"
#undef MLD_CONFIG_PARAMETER_SET
#undef MLD_H
#define MLD_CONFIG_PARAMETER_SET 87
#include "mldsa_native/mldsa_native.h"
#undef MLD_CONFIG_PARAMETER_SET
#undef MLD_H
#undef MLD_CONFIG_CONSTANTS_ONLY

#include <caml/mlvalues.h>
#include <caml/memory.h>

#define OM_STR(v) ((const uint8_t *)String_val(v))
#define OM_BYTES(v) ((uint8_t *)Bytes_val(v))
#define OM_LEN(v) caml_string_length(v)

/*
 * Instantiate one set of stubs per parameter set.
 *
 *  ocaml_mldsa_<L>_keypair    (pk:bytes) (sk:bytes) (seed:string) -> int
 *  ocaml_mldsa_<L>_pk_from_sk (pk:bytes) (sk:string) -> int
 *  ocaml_mldsa_<L>_sign       (sig:bytes) (msg:string) (ctx:string)
 *                             (rnd:string) (sk:string) -> int
 *  ocaml_mldsa_<L>_verify     (sig:string) (msg:string) (ctx:string)
 *                             (pk:string) -> int
 *  ocaml_mldsa_<L>_sign_mu    (sig:bytes) (mu:string) (rnd:string)
 *                             (sk:string) -> int
 *  ocaml_mldsa_<L>_verify_mu  (sig:string) (mu:string) (pk:string) -> int
 *
 * Return value: 0 on success, otherwise a (negative) MLD_ERR_* code.
 */
#define OM_DEFINE_LEVEL(L)                                                      \
                                                                               \
  CAMLprim value ocaml_mldsa_##L##_keypair(value pk, value sk, value seed)      \
  {                                                                            \
    if (OM_LEN(pk) != MLDSA##L##_PUBLICKEYBYTES ||                             \
        OM_LEN(sk) != MLDSA##L##_SECRETKEYBYTES ||                             \
        OM_LEN(seed) != MLDSA_SEEDBYTES)                                       \
      return Val_int(MLD_ERR_INVALID_ARG);                                     \
    return Val_int(ocaml_mldsa##L##_keypair_internal(                          \
        OM_BYTES(pk), OM_BYTES(sk), OM_STR(seed)));                            \
  }                                                                            \
                                                                               \
  CAMLprim value ocaml_mldsa_##L##_pk_from_sk(value pk, value sk)              \
  {                                                                            \
    if (OM_LEN(pk) != MLDSA##L##_PUBLICKEYBYTES ||                             \
        OM_LEN(sk) != MLDSA##L##_SECRETKEYBYTES)                               \
      return Val_int(MLD_ERR_INVALID_ARG);                                     \
    return Val_int(ocaml_mldsa##L##_pk_from_sk(OM_BYTES(pk), OM_STR(sk)));     \
  }                                                                            \
                                                                               \
  CAMLprim value ocaml_mldsa_##L##_sign(value sig, value msg, value ctx,        \
                                        value rnd, value sk)                   \
  {                                                                            \
    uint8_t pre[MLD_DOMAIN_SEPARATION_MAX_BYTES];                              \
    size_t prelen;                                                             \
    int rc;                                                                    \
    if (OM_LEN(sig) != MLDSA##L##_BYTES ||                                     \
        OM_LEN(sk) != MLDSA##L##_SECRETKEYBYTES ||                             \
        OM_LEN(rnd) != MLDSA_RNDBYTES || OM_LEN(ctx) > 255)                    \
      return Val_int(MLD_ERR_INVALID_ARG);                                     \
    /* pre = 0x00 || len(ctx) || ctx  (FIPS 204, Alg. 2 line 10) */            \
    prelen = ocaml_mldsa##L##_prepare_domain_separation_prefix(                \
        pre, NULL, 0, OM_STR(ctx), OM_LEN(ctx), MLD_PREHASH_NONE);             \
    if (prelen == 0)                                                           \
      return Val_int(MLD_ERR_INVALID_ARG);                                     \
    rc = ocaml_mldsa##L##_signature_internal(OM_BYTES(sig), OM_STR(msg),       \
                                             OM_LEN(msg), pre, prelen,         \
                                             OM_STR(rnd), OM_STR(sk), 0);      \
    return Val_int(rc);                                                        \
  }                                                                            \
                                                                               \
  CAMLprim value ocaml_mldsa_##L##_verify(value sig, value msg, value ctx,      \
                                          value pk)                            \
  {                                                                            \
    if (OM_LEN(sig) != MLDSA##L##_BYTES ||                                     \
        OM_LEN(pk) != MLDSA##L##_PUBLICKEYBYTES || OM_LEN(ctx) > 255)          \
      return Val_int(MLD_ERR_INVALID_ARG);                                     \
    return Val_int(ocaml_mldsa##L##_verify(OM_STR(sig), OM_STR(msg),           \
                                           OM_LEN(msg), OM_STR(ctx),           \
                                           OM_LEN(ctx), OM_STR(pk)));          \
  }                                                                            \
                                                                               \
  CAMLprim value ocaml_mldsa_##L##_sign_mu(value sig, value mu, value rnd,      \
                                           value sk)                           \
  {                                                                            \
    if (OM_LEN(sig) != MLDSA##L##_BYTES ||                                     \
        OM_LEN(sk) != MLDSA##L##_SECRETKEYBYTES ||                             \
        OM_LEN(rnd) != MLDSA_RNDBYTES || OM_LEN(mu) != MLDSA_CRHBYTES)         \
      return Val_int(MLD_ERR_INVALID_ARG);                                     \
    return Val_int(ocaml_mldsa##L##_signature_internal(                        \
        OM_BYTES(sig), OM_STR(mu), MLDSA_CRHBYTES, NULL, 0, OM_STR(rnd),       \
        OM_STR(sk), 1));                                                       \
  }                                                                            \
                                                                               \
  CAMLprim value ocaml_mldsa_##L##_verify_mu(value sig, value mu, value pk)     \
  {                                                                            \
    if (OM_LEN(sig) != MLDSA##L##_BYTES ||                                     \
        OM_LEN(pk) != MLDSA##L##_PUBLICKEYBYTES || OM_LEN(mu) != MLDSA_CRHBYTES) \
      return Val_int(MLD_ERR_INVALID_ARG);                                     \
    return Val_int(ocaml_mldsa##L##_verify_internal(                           \
        OM_STR(sig), OM_STR(mu), MLDSA_CRHBYTES, NULL, 0, OM_STR(pk), 1));     \
  }

OM_DEFINE_LEVEL(44)
OM_DEFINE_LEVEL(65)
OM_DEFINE_LEVEL(87)

/* Sanity: the OCaml side hard-codes these sizes (Mldsa.MldsaNN.*_length).
 * Fail the build, not the runtime, if upstream ever changes them. */
typedef char om_assert_pk44[(MLDSA44_PUBLICKEYBYTES == 1312) ? 1 : -1];
typedef char om_assert_sk44[(MLDSA44_SECRETKEYBYTES == 2560) ? 1 : -1];
typedef char om_assert_sg44[(MLDSA44_BYTES == 2420) ? 1 : -1];
typedef char om_assert_pk65[(MLDSA65_PUBLICKEYBYTES == 1952) ? 1 : -1];
typedef char om_assert_sk65[(MLDSA65_SECRETKEYBYTES == 4032) ? 1 : -1];
typedef char om_assert_sg65[(MLDSA65_BYTES == 3309) ? 1 : -1];
typedef char om_assert_pk87[(MLDSA87_PUBLICKEYBYTES == 2592) ? 1 : -1];
typedef char om_assert_sk87[(MLDSA87_SECRETKEYBYTES == 4896) ? 1 : -1];
typedef char om_assert_sg87[(MLDSA87_BYTES == 4627) ? 1 : -1];
typedef char om_assert_seed[(MLDSA_SEEDBYTES == 32 && MLDSA_RNDBYTES == 32 &&
                             MLDSA_CRHBYTES == 64) ? 1 : -1];
