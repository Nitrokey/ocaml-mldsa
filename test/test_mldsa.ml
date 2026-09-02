(* Tests for the mldsa bindings: known-answer tests against the upstream
   vectors, round trips, and negative cases. Dependency-free on purpose. *)

let hex_to_string h =
  let n = String.length h / 2 in
  String.init n (fun i -> Char.chr (int_of_string ("0x" ^ String.sub h (2 * i) 2)))

let failures = ref 0
let check name b =
  if b then Printf.printf "  ok   %s\n" name
  else (incr failures; Printf.printf "  FAIL %s\n" name)

let get = function Ok x -> x | Error e -> Format.kasprintf failwith "%a" Mldsa.pp_error e

let flip s i =
  let b = Bytes.of_string s in
  Bytes.set b i (Char.chr (Char.code (Bytes.get b i) lxor 1));
  Bytes.to_string b

module Kat (D : Mldsa.S) (V : sig
  val pk : string
  val sk : string
  val sg : string
  val sg_extmu : string
end) =
struct
  let run () =
    Printf.printf "%s\n" D.name;
    let seed = hex_to_string Vectors.test_vector_rnd in
    let rnd = seed in
    let pk = hex_to_string V.pk and sk = hex_to_string V.sk in
    let sg = hex_to_string V.sg and sg_extmu = hex_to_string V.sg_extmu in
    let mu = hex_to_string Vectors.test_vector_mu in
    check "vector lengths"
      (String.length pk = D.public_key_length
       && String.length sk = D.secret_key_length
       && String.length sg = D.signature_length);

    (* KAT: keygen *)
    let priv, pub = D.generate ~seed in
    check "KAT keypair pk" (D.pub_to_octets pub = pk);
    check "KAT keypair sk" (D.priv_to_octets priv = sk);

    (* KAT: import + validation *)
    let priv' = get (D.priv_of_octets sk) in
    check "priv_of_octets recomputes pk" (D.pub_to_octets (D.pub_of_priv priv') = pk);
    let pub' = get (D.pub_of_octets pk) in

    (* KAT: deterministic-rnd signature with context *)
    check "KAT signature (ctx, rnd)"
      (get (D.sign ~ctx:Vectors.ctx ~rnd priv Vectors.msg) = sg);
    check "KAT verify" (D.verify ~ctx:Vectors.ctx pub' ~msg:Vectors.msg sg);

    (* KAT: external mu *)
    check "KAT signature extmu" (get (D.sign_mu ~rnd priv mu) = sg_extmu);
    check "KAT verify_mu" (D.verify_mu pub' ~mu sg_extmu);

    (* round trips *)
    let msg2 = String.make 100_000 'x' in
    let s2 = get (D.sign ~rnd priv msg2) in
    check "sign/verify long message, empty ctx" (D.verify pub ~msg:msg2 s2);
    check "sign_deterministic is deterministic"
      (get (D.sign_deterministic priv msg2) = get (D.sign_deterministic priv msg2));
    check "different rnd -> different signature (hedged)"
      (get (D.sign ~rnd:(String.make 32 '\001') priv msg2) <> s2);

    (* negatives *)
    check "wrong ctx rejected" (not (D.verify ~ctx:"other" pub' ~msg:Vectors.msg sg));
    check "missing ctx rejected" (not (D.verify pub' ~msg:Vectors.msg sg));
    check "tampered msg rejected" (not (D.verify ~ctx:Vectors.ctx pub' ~msg:(Vectors.msg ^ " ") sg));
    check "tampered sig rejected" (not (D.verify ~ctx:Vectors.ctx pub' ~msg:Vectors.msg (flip sg 100)));
    check "tampered sig -> `Invalid_signature"
      (D.verify_result ~ctx:Vectors.ctx pub' ~msg:Vectors.msg (flip sg 100) = Error `Invalid_signature);
    check "short sig -> `Invalid_length"
      (D.verify_result pub' ~msg:Vectors.msg "abc" = Error (`Invalid_length "signature"));
    check "ctx > 255 rejected on sign"
      (D.sign ~ctx:(String.make 256 'c') ~rnd priv "m" = Error `Context_too_long);
    check "ctx = 255 accepted on sign"
      (Result.is_ok (D.sign ~ctx:(String.make 255 'c') ~rnd priv "m"));
    check "corrupted sk rejected by priv_of_octets"
      (D.priv_of_octets (flip sk 1500) = Error `Invalid_key);
    check "short sk rejected"
      (D.priv_of_octets "short" = Error (`Invalid_length "secret key"));
    check "short pk rejected"
      (D.pub_of_octets "short" = Error (`Invalid_length "public key"));
    check "bad seed length raises Invalid_argument"
      (match D.generate ~seed:"tooshort" with
       | exception Invalid_argument _ -> true
       | _ -> false);
    check "bad rnd length raises Invalid_argument"
      (match D.sign ~rnd:"x" priv "m" with
       | exception Invalid_argument _ -> true
       | _ -> false);
    check "bad mu length -> `Invalid_length"
      (D.sign_mu ~rnd priv "short" = Error (`Invalid_length "mu"));
    check "verify_mu bad mu length false" (not (D.verify_mu pub' ~mu:"short" sg_extmu))
end

module K44 = Kat (Mldsa.Mldsa44) (struct
  let pk = Vectors.test_vector_pk_44 let sk = Vectors.test_vector_sk_44
  let sg = Vectors.test_vector_sig_44 let sg_extmu = Vectors.test_vector_sig_extmu_44 end)
module K65 = Kat (Mldsa.Mldsa65) (struct
  let pk = Vectors.test_vector_pk_65 let sk = Vectors.test_vector_sk_65
  let sg = Vectors.test_vector_sig_65 let sg_extmu = Vectors.test_vector_sig_extmu_65 end)
module K87 = Kat (Mldsa.Mldsa87) (struct
  let pk = Vectors.test_vector_pk_87 let sk = Vectors.test_vector_sk_87
  let sg = Vectors.test_vector_sig_87 let sg_extmu = Vectors.test_vector_sig_extmu_87 end)

let () =
  K44.run (); K65.run (); K87.run ();
  if !failures > 0 then (Printf.printf "%d FAILURES\n" !failures; exit 1)
  else print_endline "all tests passed"
