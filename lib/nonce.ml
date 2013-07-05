open Ctypes
open Unsigned

type t = uchar Array.t

let zero k = Array.make uchar ~initial:UChar.zero k

let to_octets nonce = nonce
