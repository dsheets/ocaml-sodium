(** A binding to {{: https://github.com/jedisct1/libsodium } libsodium}
    which wraps {{: http://nacl.cr.yp.to/ } NaCl} *)

(** Raised when decryption/authentication fails *)
exception VerificationFailure
(** Raised when provided key is not valid *)
exception KeyError
(** Raised when provided nonce is not valid *)
exception NonceError
(** Raised when provided seed is not valid *)
exception SeedError

type public
type secret
type channel

type octets

module Serialize : sig
  module type S = sig
    type t

    val length : t -> int
    val of_octets : int -> octets -> t
    val into_octets : t -> int -> octets -> unit
  end

  module String : S with type t = string
  module Bigarray :
    S with type t = (char,
                     Bigarray.int8_unsigned_elt,
                     Bigarray.c_layout) Bigarray.Array1.t
end

module Random : sig
  val stir : unit -> unit

  module Make : functor (T : Serialize.S) -> sig
    val gen : int -> T.t
  end
end

module Box : sig
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

  (** Overwrite the key with random bytes *)
  val wipe_key : 'a key -> unit

  val compare_keys : public key -> public key -> int

  module Make : functor (T : Serialize.S) -> sig
    val box_write_key : 'a key -> T.t
    (** Can raise {! exception : KeyError } *)
    val box_read_public_key : T.t -> public key
    (** Can raise {! exception : KeyError } *)
    val box_read_secret_key : T.t -> secret key
    (** Can raise {! exception : KeyError } *)
    val box_read_channel_key: T.t -> channel key

    val box_write_nonce : nonce -> T.t
    (** Can raise {! exception : NonceError } *)
    val box_read_nonce : T.t -> nonce

    val box_write_ciphertext : ciphertext -> T.t
    val box_read_ciphertext : T.t -> ciphertext

    val box_keypair : unit -> public key * secret key
    val box :
      secret key -> public key -> T.t -> nonce:nonce -> ciphertext
    (** Can raise {! exception : VerificationFailure } *)
    val box_open :
      secret key -> public key -> ciphertext -> nonce:nonce -> T.t
    val box_beforenm : secret key -> public key -> channel key
    val box_afternm : channel key -> T.t -> nonce:nonce -> ciphertext
    (** Can raise {! exception : VerificationFailure } *)
    val box_open_afternm : channel key -> ciphertext -> nonce:nonce -> T.t
  end
end

module Sign : sig
  type 'a key

  type sizes = {
    public_key : int;
    secret_key : int;
    seed       : int;
    signature  : int;
  }

  val bytes : sizes
  val crypto_module : string
  val ciphersuite : string

  (** Overwrite the key with random bytes *)
  val wipe_key : 'a key -> unit

  val compare_keys : public key -> public key -> int

  module Make : functor (T : Serialize.S) -> sig
    val sign_write_key : 'a key -> T.t
    (** Can raise {! exception : KeyError } *)
    val sign_read_public_key : T.t -> public key
    (** Can raise {! exception : KeyError } *)
    val sign_read_secret_key : T.t -> secret key

    (** Can raise {! exception : SeedError } *)
    val sign_seed_keypair : T.t -> public key * secret key
    val sign_keypair : unit -> public key * secret key
    val sign : secret key -> T.t -> T.t
    (** Can raise {! exception : VerificationFailure } *)
    val sign_open : public key -> T.t -> T.t
  end
end

module Make : functor (T : Serialize.S) -> sig
  include module type of Box.Make(T)
  include module type of Sign.Make(T)
end
