(** ML-DSA (FIPS 204) digital signatures.

    Bindings to {{:https://github.com/pq-code-package/mldsa-native}mldsa-native}.
    The portable C90 implementation is embedded in this library (compiled as
    foreign stubs), so there is no dynamically linked C library and the package
    cross-compiles for MirageOS.

    This library is deliberately free of an RNG dependency: key generation
    takes a 32-byte {e seed} and signing takes 32 bytes of fresh randomness
    [rnd] (hedged signing, FIPS 204 §3.4).  Use {!Mldsa_rng} (package
    [mldsa-native-rng]) to obtain both from [Mirage_crypto_rng], or supply them from
    the RNG of your choice. *)

(** Errors reported when handling externally supplied data. *)
type error =
  [ `Invalid_length of string
    (** A key / signature / mu had the wrong length; the payload names it. *)
  | `Invalid_key  (** Secret key failed consistency checks. *)
  | `Invalid_signature  (** Signature did not verify. *)
  | `Context_too_long  (** [ctx] exceeded 255 bytes. *)
  | `Sign_attempts_exhausted
    (** The rejection-sampling loop hit the compile-time attempt limit
        (astronomically unlikely with honest randomness). *)
  | `Internal of int  (** Unexpected mldsa-native error code. *) ]

val pp_error : Format.formatter -> error -> unit

(** Common interface of the three parameter sets. *)
module type S = sig
  val name : string
  (** ["ML-DSA-44"] etc. *)

  val level : int
  (** [44], [65] or [87]. *)

  val public_key_length : int
  val secret_key_length : int
  val signature_length : int

  val seed_length : int
  (** Key-generation seed size, 32. *)

  val rnd_length : int
  (** Per-signature randomness size, 32. *)

  val mu_length : int
  (** Size of an externally computed message representative [mu], 64. *)

  type priv
  type pub

  (** {1 Keys} *)

  val generate : seed:string -> priv * pub
  (** [generate ~seed] derives a key pair from a uniformly random 32-byte seed
      (FIPS 204 Algorithm 6, [ML-DSA.KeyGen_internal]).  The seed must come
      from a cryptographically secure RNG.
      @raise Invalid_argument if [seed] is not {!seed_length} bytes. *)

  val pub_of_priv : priv -> pub

  val priv_of_octets : string -> (priv, error) result
  (** Imports a serialized secret key.  Besides the length check, the key is
      validated by recomputing the public key ([pk_from_sk] upstream), so a
      corrupted key is rejected with [`Invalid_key].  Validation is not
      constant time; do not use it on secret keys of unknown origin in a
      context where timing matters. *)

  val priv_to_octets : priv -> string

  val pub_of_octets : string -> (pub, error) result
  (** Imports a serialized public key (length check only). *)

  val pub_to_octets : pub -> string

  (** {1 Pure ML-DSA} *)

  val sign : ?ctx:string -> rnd:string -> priv -> string -> (string, error) result
  (** [sign ?ctx ~rnd priv msg] signs [msg] with optional context string
      [ctx] (at most 255 bytes, default [""]) using fresh randomness [rnd]
      (hedged variant).  Passing 32 zero bytes as [rnd] yields the
      deterministic variant of FIPS 204; see {!sign_deterministic}.
      @raise Invalid_argument if [rnd] is not {!rnd_length} bytes. *)

  val sign_deterministic : ?ctx:string -> priv -> string -> (string, error) result
  (** Deterministic ML-DSA ([rnd] = zeros).  FIPS 204 advises against it on
      platforms where fault or side-channel attacks are a concern. *)

  val verify : ?ctx:string -> pub -> msg:string -> string -> bool
  (** [verify ?ctx pub ~msg signature].  Returns [false] for a signature of
      the wrong length, a too-long [ctx], or a failed check. *)

  val verify_result : ?ctx:string -> pub -> msg:string -> string -> (unit, error) result
  (** As {!verify} but tells you why. *)

  (** {1 External mu} *)

  (** "External mu" mode (NIST FIPS 204 §6 guidance): the caller computes the
      64-byte message representative
      [mu = SHAKE256(tr || 0x00 || len(ctx) || ctx || msg, 64)]
      where [tr = SHAKE256(pk, 64)], e.g. on a host, and the signer only
      sees [mu].  Useful when the message is large or streamed, and for HSM
      style deployments. *)

  val sign_mu : rnd:string -> priv -> string -> (string, error) result
  (** @raise Invalid_argument if [rnd] is not {!rnd_length} bytes. *)

  val verify_mu : pub -> mu:string -> string -> bool
end

module Mldsa44 : S
module Mldsa65 : S
module Mldsa87 : S
