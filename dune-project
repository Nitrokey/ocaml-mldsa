(lang dune 3.5)
(name mldsa)

(generate_opam_files true)

(source (github nitrokey/ocaml-mldsa))
(license "Apache-2.0 OR ISC OR MIT")
(authors "Nitrokey GmbH")
(maintainers "Nitrokey GmbH")

(package
 (name mldsa)
 (synopsis "ML-DSA (FIPS 204) signatures with the C code of mldsa-native embedded")
 (description
  "OCaml bindings to mldsa-native (https://github.com/pq-code-package/mldsa-native).
The portable C implementation is vendored and compiled into the OCaml library
as foreign stubs, with no dynamically linked dependency, so the library can be
cross-compiled for MirageOS/solo5.  Randomness is passed in explicitly; see the
mldsa-rng package for Mirage_crypto_rng integration.")
 (depends
  (ocaml (>= 4.13.0))))

(package
 (name mldsa-rng)
 (synopsis "ML-DSA key generation and hedged signing using Mirage_crypto_rng")
 (depends
  (ocaml (>= 4.13.0))
  (mldsa (= :version))
  (mirage-crypto-rng (>= 1.0.0))))
