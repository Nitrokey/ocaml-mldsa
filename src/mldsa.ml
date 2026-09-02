type error =
  [ `Invalid_length of string
  | `Invalid_key
  | `Invalid_signature
  | `Context_too_long
  | `Sign_attempts_exhausted
  | `Internal of int ]

let pp_error ppf = function
  | `Invalid_length what -> Format.fprintf ppf "invalid length of %s" what
  | `Invalid_key -> Format.pp_print_string ppf "invalid secret key"
  | `Invalid_signature -> Format.pp_print_string ppf "invalid signature"
  | `Context_too_long -> Format.pp_print_string ppf "context string longer than 255 bytes"
  | `Sign_attempts_exhausted -> Format.pp_print_string ppf "signing attempts exhausted"
  | `Internal rc -> Format.fprintf ppf "internal mldsa-native error %d" rc

(* Error codes from mldsa_native.h; keep in sync (the stubs pass them
   through unchanged). *)
let err_of_rc = function
  | 0 -> Ok ()
  | -1 -> Error (`Internal (-1)) (* MLD_ERR_FAIL *)
  | -2 -> Error (`Internal (-2)) (* MLD_ERR_OUT_OF_MEMORY: not possible, stack allocation *)
  | -3 -> Error (`Internal (-3)) (* MLD_ERR_RNG_FAIL: no RNG in our build *)
  | -4 -> Error `Sign_attempts_exhausted
  | -5 -> Error (`Internal (-5)) (* MLD_ERR_SIGNING_PAUSED: hooks disabled *)
  | -6 -> Error `Invalid_signature
  | -7 -> Error `Invalid_key
  | -8 -> Error (`Internal (-8)) (* MLD_ERR_PCT_FAIL: PCT disabled *)
  | -9 -> Error `Context_too_long (* MLD_ERR_INVALID_ARG; lengths are pre-checked *)
  | rc -> Error (`Internal rc)

module type S = sig
  val name : string
  val level : int
  val public_key_length : int
  val secret_key_length : int
  val signature_length : int
  val seed_length : int
  val rnd_length : int
  val mu_length : int
  type priv
  type pub
  val generate : seed:string -> priv * pub
  val pub_of_priv : priv -> pub
  val priv_of_octets : string -> (priv, error) result
  val priv_to_octets : priv -> string
  val pub_of_octets : string -> (pub, error) result
  val pub_to_octets : pub -> string
  val sign : ?ctx:string -> rnd:string -> priv -> string -> (string, error) result
  val sign_deterministic : ?ctx:string -> priv -> string -> (string, error) result
  val verify : ?ctx:string -> pub -> msg:string -> string -> bool
  val verify_result : ?ctx:string -> pub -> msg:string -> string -> (unit, error) result
  val sign_mu : rnd:string -> priv -> string -> (string, error) result
  val verify_mu : pub -> mu:string -> string -> bool
end

(* Raw C entry points for one parameter set. All are [@@noalloc]: they do not
   allocate, do not raise and do not touch the GC, so we may pass bytes/string
   pointers straight through (see mldsa_stubs.c). *)
module type Stubs = sig
  val level : int
  val public_key_length : int
  val secret_key_length : int
  val signature_length : int
  val keypair : bytes -> bytes -> string -> int
  val pk_from_sk : bytes -> string -> int
  val sign : bytes -> string -> string -> string -> string -> int
  val verify : string -> string -> string -> string -> int
  val sign_mu : bytes -> string -> string -> string -> int
  val verify_mu : string -> string -> string -> int
end

module Make (C : Stubs) : S = struct
  let level = C.level
  let name = "ML-DSA-" ^ string_of_int level
  let public_key_length = C.public_key_length
  let secret_key_length = C.secret_key_length
  let signature_length = C.signature_length
  let seed_length = 32
  let rnd_length = 32
  let mu_length = 64

  (* Keys are kept in their FIPS 204 bit-packed serialization; [pub] is
     stored alongside [priv] so that [pub_of_priv] is free. *)
  type pub = string
  type priv = { sk : string; pk : pub }

  let check_len what expected s =
    if String.length s = expected then Ok ()
    else Error (`Invalid_length what)

  let invalid_arg_len what expected s =
    if String.length s <> expected then
      invalid_arg
        (Printf.sprintf "%s: %s must be %d bytes, got %d" name what expected
           (String.length s))

  let generate ~seed =
    invalid_arg_len "seed" seed_length seed;
    let pk = Bytes.create public_key_length
    and sk = Bytes.create secret_key_length in
    match err_of_rc (C.keypair pk sk seed) with
    | Ok () ->
      let pk = Bytes.unsafe_to_string pk and sk = Bytes.unsafe_to_string sk in
      ({ sk; pk }, pk)
    | Error e ->
      (* keypair_internal cannot fail in this configuration (no PCT, no
         allocation); an error here is a bug, not bad input. *)
      Format.kasprintf failwith "%s: key generation failed: %a" name pp_error e

  let pub_of_priv { pk; _ } = pk

  let priv_of_octets sk =
    match check_len "secret key" secret_key_length sk with
    | Error _ as e -> e
    | Ok () ->
      let pk = Bytes.create public_key_length in
      match err_of_rc (C.pk_from_sk pk sk) with
      | Ok () -> Ok { sk; pk = Bytes.unsafe_to_string pk }
      | Error _ as e -> e

  let priv_to_octets { sk; _ } = sk

  let pub_of_octets pk =
    match check_len "public key" public_key_length pk with
    | Ok () -> Ok pk
    | Error _ as e -> e

  let pub_to_octets pk = pk

  let check_ctx = function
    | Some c when String.length c > 255 -> Error `Context_too_long
    | Some c -> Ok c
    | None -> Ok ""

  let sign ?ctx ~rnd { sk; _ } msg =
    invalid_arg_len "rnd" rnd_length rnd;
    match check_ctx ctx with
    | Error _ as e -> e
    | Ok ctx ->
      let sg = Bytes.create signature_length in
      match err_of_rc (C.sign sg msg ctx rnd sk) with
      | Ok () -> Ok (Bytes.unsafe_to_string sg)
      | Error _ as e -> e

  let zero_rnd = String.make rnd_length '\000'
  let sign_deterministic ?ctx priv msg = sign ?ctx ~rnd:zero_rnd priv msg

  let verify_result ?ctx pk ~msg sg =
    match check_ctx ctx with
    | Error _ as e -> e
    | Ok ctx ->
      match check_len "signature" signature_length sg with
      | Error _ as e -> e
      | Ok () -> err_of_rc (C.verify sg msg ctx pk)

  let verify ?ctx pk ~msg sg =
    match verify_result ?ctx pk ~msg sg with Ok () -> true | Error _ -> false

  let sign_mu ~rnd { sk; _ } mu =
    invalid_arg_len "rnd" rnd_length rnd;
    match check_len "mu" mu_length mu with
    | Error _ as e -> e
    | Ok () ->
      let sg = Bytes.create signature_length in
      match err_of_rc (C.sign_mu sg mu rnd sk) with
      | Ok () -> Ok (Bytes.unsafe_to_string sg)
      | Error _ as e -> e

  let verify_mu pk ~mu sg =
    String.length mu = mu_length
    && String.length sg = signature_length
    && C.verify_mu sg mu pk = 0
end

module Mldsa44 = Make (struct
  let level = 44
  let public_key_length = 1312
  let secret_key_length = 2560
  let signature_length = 2420
  external keypair : bytes -> bytes -> string -> int = "ocaml_mldsa_44_keypair" [@@noalloc]
  external pk_from_sk : bytes -> string -> int = "ocaml_mldsa_44_pk_from_sk" [@@noalloc]
  external sign : bytes -> string -> string -> string -> string -> int = "ocaml_mldsa_44_sign" [@@noalloc]
  external verify : string -> string -> string -> string -> int = "ocaml_mldsa_44_verify" [@@noalloc]
  external sign_mu : bytes -> string -> string -> string -> int = "ocaml_mldsa_44_sign_mu" [@@noalloc]
  external verify_mu : string -> string -> string -> int = "ocaml_mldsa_44_verify_mu" [@@noalloc]
end)

module Mldsa65 = Make (struct
  let level = 65
  let public_key_length = 1952
  let secret_key_length = 4032
  let signature_length = 3309
  external keypair : bytes -> bytes -> string -> int = "ocaml_mldsa_65_keypair" [@@noalloc]
  external pk_from_sk : bytes -> string -> int = "ocaml_mldsa_65_pk_from_sk" [@@noalloc]
  external sign : bytes -> string -> string -> string -> string -> int = "ocaml_mldsa_65_sign" [@@noalloc]
  external verify : string -> string -> string -> string -> int = "ocaml_mldsa_65_verify" [@@noalloc]
  external sign_mu : bytes -> string -> string -> string -> int = "ocaml_mldsa_65_sign_mu" [@@noalloc]
  external verify_mu : string -> string -> string -> int = "ocaml_mldsa_65_verify_mu" [@@noalloc]
end)

module Mldsa87 = Make (struct
  let level = 87
  let public_key_length = 2592
  let secret_key_length = 4896
  let signature_length = 4627
  external keypair : bytes -> bytes -> string -> int = "ocaml_mldsa_87_keypair" [@@noalloc]
  external pk_from_sk : bytes -> string -> int = "ocaml_mldsa_87_pk_from_sk" [@@noalloc]
  external sign : bytes -> string -> string -> string -> string -> int = "ocaml_mldsa_87_sign" [@@noalloc]
  external verify : string -> string -> string -> string -> int = "ocaml_mldsa_87_verify" [@@noalloc]
  external sign_mu : bytes -> string -> string -> string -> int = "ocaml_mldsa_87_sign_mu" [@@noalloc]
  external verify_mu : string -> string -> string -> int = "ocaml_mldsa_87_verify_mu" [@@noalloc]
end)
