# ocaml-mldsa — ML-DSA (FIPS 204) for OCaml and MirageOS

OCaml bindings to [mldsa-native](https://github.com/pq-code-package/mldsa-native),
the formally verified, portable C90 implementation of the ML-DSA post-quantum
signature scheme.

The C code is **embedded in the OCaml library** as dune `foreign_stubs`. 
There is no shared library, no `pkg-config`, no `randombytes()` to provide:
the resulting `.cmxa` plus `libmldsa_stubs.a` is self-contained and only
needs `memcpy`/`memset` from the target's libc (or `nolibc` on solo5).  That
makes it usable from cross-compiled MirageOS unikernels (`dune build -x
solo5 …`) with no extra work.

Two opam packages:

| package     | contents                                                                                    | deps                 |
|-------------|---------------------------------------------------------------------------------------------|----------------------|
| `mldsa`     | `Mldsa.Mldsa44/65/87` — keygen from a seed, sign (hedged/deterministic), verify, external mu | none                 |
| `mldsa-rng` | `Mldsa_rng.Mldsa44/65/87` — same, with seed/`rnd` drawn from `Mirage_crypto_rng`             | `mirage-crypto-rng`  |

The split keeps the C-embedding core free of dependencies; the RNG glue is a
few lines and easy to replace if NetHSM wants to source randomness differently.

## Usage

```ocaml
let () =
  Mirage_crypto_rng_unix.use_default ();
  let module D = Mldsa_rng.Mldsa65 in
  let priv, pub = D.generate () in
  match D.sign ~ctx:"my-app" priv "message" with
  | Ok signature ->
    assert (D.verify ~ctx:"my-app" pub ~msg:"message" signature);
    (* serialise: *)
    let sk = D.priv_to_octets priv and pk = D.pub_to_octets pub in
    ignore (sk, pk)
  | Error e -> Format.eprintf "%a@." Mldsa.pp_error e
```

Without an RNG dependency, supply the 32 random bytes yourself:

```ocaml
let priv, pub = Mldsa.Mldsa87.generate ~seed in
let sg = Mldsa.Mldsa87.sign ~rnd priv msg   (* rnd = 32 fresh bytes, or zeros for deterministic *)
```

`sign_mu`/`verify_mu` implement the "external mu" mode (NIST FIPS 204 §6
guidance) where the caller pre-computes `mu = SHAKE256(tr || 0x00 || |ctx| || ctx || M, 64)`
and only `mu` reaches the signer — relevant for HSM-style designs and large
or streamed messages.

## Layout

```
src/mldsa.ml(i)                    OCaml API
src/mldsa_stubs.c                  the ONLY C translation unit: includes everything below + CAMLprim wrappers
src/native/mldsa_ocaml_config.h    mldsa-native configuration (multi-level, static, no randombytes)
src/native/mldsa_native_all.c      includes mldsa_native.c three times (44/65/87), as in upstream's
                                   examples/monolithic_build_multilevel
src/native/mldsa_native/           vendored upstream sources (C + aarch64/x86-64 asm) — do not edit, run ./vendor.sh
src/gen_arch_flags.ml              target-specific flags (-mavx2 -mbmi2 / -mcpu=cortex-a76)
rng/                               mldsa-rng
test/                              known-answer tests (vectors from upstream) + round trips + negatives
vendor.sh, VENDORED                re-vendoring script and the pinned upstream commit
```

### Design notes

* **Deterministic C API only.** The stubs call `keypair_internal`,
  `signature_internal` and `verify(_internal)` and the build sets
  `MLD_CONFIG_NO_RANDOMIZED_API`, so mldsa-native never calls `randombytes()`.
  Randomness is an explicit argument on the OCaml side.
* **Single translation unit, everything `static`.** With
  `MLD_CONFIG_{INTERNAL,EXTERNAL}_API_QUALIFIER static` the archive exports
  exactly the 18 `ocaml_mldsa_*` stubs (`nm -g libmldsa_stubs.a`). Linking a
  unikernel that also contains liboqs or another mldsa-native copy cannot
  clash.
* **Native backends, selected by the target compiler.** mldsa-native picks
  its arithmetic and Keccak backends at preprocessing time from the compiler's
  predefined macros (`__aarch64__`, `__x86_64__` + `__AVX2__`), and the
  bundle `mldsa_native_asm.S` includes only the matching assembly. With dune,
  "the compiler" is the active toolchain's, so `dune build -x solo5` on an
  aarch64 target gets Neon and an x86-64 target gets AVX2 — one package, no
  per-architecture variants. `src/gen_arch_flags.ml` adds the target flags:
  `-mavx2 -mbmi2` on x86-64 (AVX2 is assumed present; no runtime CPUID),
  `-mcpu=cortex-a76` on aarch64 (Raspberry Pi 5; deliberately no `+sha3`,
  the A76 lacks EOR3, so the scalar/Neon Keccak variants are used). Any other
  architecture falls back to portable C automatically. Overrides:
  `MLDSA_ARCH_CFLAGS="..."` replaces the target flags (`none` for no flags;
  e.g. use `none` or `-mcpu=cortex-a72` for a Pi 4, since A76 code generation
  may use Armv8.2 instructions), `-DMLDSA_OCAML_NO_NATIVE` forces the portable
  C backends. The assembly is linked as a separate `libmldsa_asm.a`
  (`foreign_archives`), so the library is `(modes native)` only.
  Measured on ML-DSA-87 (x86-64, AVX2 vs portable C): keygen 66 vs 172 µs,
  sign 192 vs 483 µs, verify 64 vs 147 µs.
* **Stack usage.** Default configuration allocates working buffers on the C
  stack: ~107 KB for ML-DSA-87 signing, ~69 KB verify (see `MLD_TOTAL_ALLOC_*`
  in `mldsa_native.h`). Fine for solo5 and for OCaml 5 (C stubs run on the
  system stack). If a target has a small C stack, build with
  `-DMLDSA_OCAML_REDUCE_RAM` (→ `MLD_CONFIG_REDUCE_RAM`, ~14 KB) — the test
  suite passes in both modes.
* **`[@@noalloc]` stubs.** No allocation, no callbacks, runtime lock held.
  Signing ML-DSA-87 takes on the order of a millisecond in portable C.
* **Exported symbols.** `libmldsa_stubs.a` exports only the 18
  `ocaml_mldsa_*` stubs; `libmldsa_asm.a` exports the backend routines under
  the same `ocaml_mldsa_` prefix (`MLD_ASM_NAMESPACE`), so linking next to
  liboqs or another mldsa-native copy still cannot clash.
* **Key import.** `priv_of_octets` validates the secret key via upstream's
  `pk_from_sk` (recomputes `t0`, `tr`, checks `s1`/`s2` bounds). This is not
  constant time; use it at import time, not per operation.

## Building and testing

```
dune build
dune test                    # 78 checks: upstream KATs for all 3 levels, round trips, negatives
MLDSA_ARCH_CFLAGS=none dune test   # same, forcing the portable C backends on x86-64
```

MirageOS: add `mldsa` (and `mldsa-rng`) to the unikernel's dependencies; the
mirage tool's `dune build -x solo5` compiles `mldsa_stubs.c` with the solo5
toolchain like any other foreign stub.

## Updating mldsa-native

```
./vendor.sh v1.0.0            # or a commit hash; updates src/native/mldsa_native and VENDORED
python3 test/gen_vectors.py <upstream>/examples/monolithic_build_multilevel/expected_test_vectors_multilevel.h > test/vectors.ml
dune test
```

`mldsa_stubs.c` contains compile-time asserts on the key/signature sizes, so an
upstream change to those constants fails the build instead of the tests.

## License

The bindings are `Apache-2.0 OR ISC OR MIT`, matching mldsa-native
(see `src/native/mldsa_native/LICENSE`).
