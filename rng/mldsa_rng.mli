(** {!Mldsa} with randomness from [Mirage_crypto_rng].

    Thin convenience layer: seeds and per-signature randomness are drawn from
    the (optionally given) generator [g]; everything else is {!Mldsa}. *)

module type S = sig
  include Mldsa.S

  val generate : ?g:Mirage_crypto_rng.g -> unit -> priv * pub
  (** Fresh key pair from 32 random bytes. *)

  val sign : ?g:Mirage_crypto_rng.g -> ?ctx:string -> priv -> string -> (string, Mldsa.error) result
  (** Hedged signing with 32 fresh random bytes. *)

  val sign_mu : ?g:Mirage_crypto_rng.g -> priv -> string -> (string, Mldsa.error) result
end

module Make (D : Mldsa.S) : S with type priv = D.priv and type pub = D.pub

module Mldsa44 : S with type priv = Mldsa.Mldsa44.priv and type pub = Mldsa.Mldsa44.pub
module Mldsa65 : S with type priv = Mldsa.Mldsa65.priv and type pub = Mldsa.Mldsa65.pub
module Mldsa87 : S with type priv = Mldsa.Mldsa87.priv and type pub = Mldsa.Mldsa87.pub
