val crypto_module : string
val ciphersuite : string
val impl : string
val prefix : string
val box_fn_type :
  (string -> string -> Unsigned.ullong -> string -> string -> string -> int)
  Ctypes.fn
val box_afternm_type :
  (string -> string -> Unsigned.ullong -> string -> string -> int) Ctypes.fn
val box_c :
  string -> string -> Unsigned.ullong -> string -> string -> string -> int
val box_open_c :
  string -> string -> Unsigned.ullong -> string -> string -> string -> int
val box_keypair_c : string -> string -> int
val box_beforenm_c : string -> string -> string -> int
val box_afternm_c :
  string -> string -> Unsigned.ullong -> string -> string -> int
val box_open_afternm_c :
  string -> string -> Unsigned.ullong -> string -> string -> int
