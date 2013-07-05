type public_key
type secret_key

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

module C : sig
  val keypair :
    Unsigned.uchar Ctypes.ptr -> Unsigned.uchar Ctypes.ptr -> int
end

val keypair : unit -> public_key * secret_key
