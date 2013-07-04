open Ctypes
open PosixTypes
open Foreign

let crypto_module = "crypto_box"
let ciphersuite = "curve25519xsalsa20poly1305"
let impl = "ref"
let prefix = Printf.sprintf "%s_%s_%s" crypto_module ciphersuite impl

let box_fn_type = (string @-> string @-> ullong
                   @-> string @-> string @-> string
                   @-> returning int)

let box_afternm_type =
  (string @-> string @-> ullong @-> string @-> string @-> returning int)

let box_c              = foreign (prefix) box_fn_type
let box_open_c         = foreign (prefix^"_open") box_fn_type

let box_keypair_c      = foreign (prefix^"_keypair")
  (string @-> string @-> returning int)

let box_beforenm_c     = foreign (prefix^"_beforenm")
  (string @-> string @-> string @-> returning int)
let box_afternm_c      = foreign (prefix^"_afternm") box_afternm_type

let box_open_afternm_c = foreign (prefix^"_open_afternm") box_afternm_type

