module type S = sig
  include Mldsa.S
  val generate : ?g:Mirage_crypto_rng.g -> unit -> priv * pub
  val sign : ?g:Mirage_crypto_rng.g -> ?ctx:string -> priv -> string -> (string, Mldsa.error) result
  val sign_mu : ?g:Mirage_crypto_rng.g -> priv -> string -> (string, Mldsa.error) result
end

module Make (D : Mldsa.S) = struct
  include D
  let generate ?g () = D.generate ~seed:(Mirage_crypto_rng.generate ?g D.seed_length)
  let sign ?g ?ctx priv msg = D.sign ?ctx ~rnd:(Mirage_crypto_rng.generate ?g D.rnd_length) priv msg
  let sign_mu ?g priv mu = D.sign_mu ~rnd:(Mirage_crypto_rng.generate ?g D.rnd_length) priv mu
end

module Mldsa44 = Make (Mldsa.Mldsa44)
module Mldsa65 = Make (Mldsa.Mldsa65)
module Mldsa87 = Make (Mldsa.Mldsa87)
