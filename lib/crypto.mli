(** A binding to the {{: http://nacl.cr.yp.to/box.html } crypto_box}
    module of {{: https://github.com/jedisct1/libsodium } libsodium}
    wrapping {{: http://nacl.cr.yp.to/ } NaCl} *)

(** Raised when decryption/authentication fails *)
exception VerificationFailure

type octets

module Serializer : sig
  module type S = sig
    type t

    val length : t -> int
    val of_octets : int -> octets -> t
    val into_octets : t -> int -> octets -> unit
  end

  module String : S with type t = string
end

module Make : functor (T : Serializer.S) -> sig
  module Nonce : sig
    type t
  end

  module Box : sig
    type public_key
    type secret_key
    type channel_key
    type ciphertext

    type sizes = {
      public_key : int;
      secret_key : int;
      beforenm : int;
      nonce : int;
      zero : int;
      box_zero : int;
    }
    val bytes : sizes
    val crypto_module : string
    val ciphersuite : string
    val impl : string

    (** Zero the memory of the secret key *)
    val wipe : secret_key -> unit

    val serialize_public_key : public_key -> T.t
    val serialize_secret_key : secret_key -> T.t
    val serialize_channel_key: channel_key-> T.t
    val serialize_ciphertext : ciphertext -> T.t

    val keypair : unit -> public_key * secret_key
    val box : secret_key -> public_key -> T.t -> nonce:Nonce.t -> ciphertext
    val box_open : secret_key -> public_key -> ciphertext -> nonce:Nonce.t -> T.t
    val box_beforenm : secret_key -> public_key -> channel_key
    val box_afternm : channel_key -> T.t -> nonce:Nonce.t -> ciphertext
    val box_open_afternm : channel_key -> ciphertext -> nonce:Nonce.t -> T.t
  end
end
