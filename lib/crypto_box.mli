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

val string_of_public_key : public_key -> string
val string_of_secret_key : secret_key -> string
val string_of_channel_key: channel_key-> string
val string_of_ciphertext : ciphertext -> string

val keypair : unit -> public_key * secret_key
val box : secret_key -> public_key -> string -> Nonce.t -> ciphertext
val box_open : secret_key -> public_key -> ciphertext -> Nonce.t -> string
val box_beforenm : secret_key -> public_key -> channel_key
val box_afternm : channel_key -> string -> Nonce.t -> ciphertext
val box_open_afternm : channel_key -> ciphertext -> Nonce.t -> string
