type public_key
type secret_key
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
val string_of_ciphertext : ciphertext -> string

module C : sig
  type buffer = Unsigned.uchar Ctypes.ptr
  type box = buffer -> buffer -> Unsigned.ullong
      -> buffer -> buffer -> buffer -> int

  val keypair : buffer -> buffer -> int
  val box : box
  val box_open : box
end

val keypair : unit -> public_key * secret_key
val box : secret_key -> public_key -> string -> Nonce.t -> ciphertext
val box_open : secret_key -> public_key -> ciphertext -> Nonce.t -> string
