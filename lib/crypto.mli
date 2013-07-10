(** A binding to the {{: http://nacl.cr.yp.to/box.html } crypto_box}
    module of {{: https://github.com/jedisct1/libsodium } libsodium}
    wrapping {{: http://nacl.cr.yp.to/ } NaCl} *)

(** Raised when decryption/authentication fails *)
exception VerificationFailure
(** Raised when provided keys are not valid *)
exception KeyError
(** Raised when provided nonce is not valid *)
exception NonceError

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
  module Box : sig
    type public
    type secret
    type channel
    type 'a key
    type nonce
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
    val wipe : secret key -> unit

    val compare_keys : 'a key -> 'a key -> int
    val write_key : 'a key -> T.t
    val read_public_key : T.t -> public key
    val read_secret_key : T.t -> secret key
    val read_channel_key: T.t -> channel key

    val write_nonce : nonce -> T.t
    val read_nonce : T.t -> nonce

    val write_ciphertext : ciphertext -> T.t
    val read_ciphertext : T.t -> ciphertext

    val keypair : unit -> public key * secret key
    val box : secret key -> public key -> T.t -> nonce:nonce -> ciphertext
    val box_open : secret key -> public key -> ciphertext -> nonce:nonce -> T.t
    val box_beforenm : secret key -> public key -> channel key
    val box_afternm : channel key -> T.t -> nonce:nonce -> ciphertext
    val box_open_afternm : channel key -> ciphertext -> nonce:nonce -> T.t
  end
end
