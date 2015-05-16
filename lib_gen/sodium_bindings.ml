open Ctypes

module C(F: Cstubs.FOREIGN) = struct
  let prefix = "sodium"

  let init    = F.foreign (prefix^"_init")    (void @-> returning void)
  let memzero = F.foreign (prefix^"_memzero") (ocaml_bytes @-> size_t @-> returning void)
  let memcmp  = F.foreign (prefix^"_memcmp")  (ocaml_bytes @-> ocaml_bytes @-> size_t @-> returning void)

  module Verify = struct
    let verify_type = ocaml_bytes @-> ocaml_bytes @-> returning int
    let verify_16   = F.foreign "crypto_verify_16" verify_type
    let verify_32   = F.foreign "crypto_verify_32" verify_type
    let verify_64   = F.foreign "crypto_verify_64" verify_type
  end

  module Random = struct
    let stir = F.foreign "randombytes_stir" (void @-> returning void)

    module Make(T: Sodium_storage.S) = struct
      let gen  = F.foreign "randombytes_buf"  (T.ctype @-> size_t @-> returning void)
    end
  end

  module Box = struct
    let primitive = "curve25519xsalsa20poly1305"
    let prefix    = "crypto_box_"^primitive

    let sz_query_type    = void @-> returning size_t
    let publickeybytes   = F.foreign (prefix^"_publickeybytes") sz_query_type
    let secretkeybytes   = F.foreign (prefix^"_secretkeybytes") sz_query_type
    let beforenmbytes    = F.foreign (prefix^"_beforenmbytes")  sz_query_type
    let noncebytes       = F.foreign (prefix^"_noncebytes")     sz_query_type
    let zerobytes        = F.foreign (prefix^"_zerobytes")      sz_query_type
    let boxzerobytes     = F.foreign (prefix^"_boxzerobytes")   sz_query_type

    let box_keypair      = F.foreign (prefix^"_keypair")
                                     (ocaml_bytes @-> ocaml_bytes @-> returning int)

    let box_beforenm     = F.foreign (prefix^"_beforenm")
                                     (ocaml_bytes @-> ocaml_bytes @-> ocaml_bytes
                                      @-> returning int)

    module Make(T: Sodium_storage.S) = struct
      let box_fn_type      = (T.ctype @-> T.ctype @-> ullong
                              @-> ocaml_bytes @-> ocaml_bytes @-> ocaml_bytes
                              @-> returning int)

      let box              = F.foreign (prefix) box_fn_type
      let box_open         = F.foreign (prefix^"_open") box_fn_type

      let box_afternm_type = (T.ctype @-> T.ctype @-> ullong
                              @-> ocaml_bytes @-> ocaml_bytes @-> returning int)

      let box_afternm      = F.foreign (prefix^"_afternm") box_afternm_type
      let box_open_afternm = F.foreign (prefix^"_open_afternm") box_afternm_type
    end
  end

  module Sign = struct
    let primitive = "ed25519"
    let prefix    = "crypto_sign_"^primitive

    let sz_query_type   = void @-> returning size_t
    let publickeybytes  = F.foreign (prefix^"_publickeybytes") sz_query_type
    let secretkeybytes  = F.foreign (prefix^"_secretkeybytes") sz_query_type
    let bytes           = F.foreign (prefix^"_bytes")          sz_query_type
    let seedbytes       = F.foreign (prefix^"_seedbytes")      sz_query_type

    let sign_keypair    = F.foreign (prefix^"_keypair")
                                    (ocaml_bytes @-> ocaml_bytes
                                     @-> returning int)
    let sign_seed_keypair = F.foreign (prefix^"_seed_keypair")
                                      (ocaml_bytes @-> ocaml_bytes @-> ocaml_bytes
                                       @-> returning int)

    let sign_sk_to_seed = F.foreign (prefix^"_sk_to_seed")
                                    (ocaml_bytes @-> ocaml_bytes
                                     @-> returning int)
    let sign_sk_to_pk   = F.foreign (prefix^"_sk_to_pk")
                                    (ocaml_bytes @-> ocaml_bytes
                                     @-> returning int)

    let to_curve_25519_type = (ocaml_bytes @-> ocaml_bytes @-> returning int)
    let sign_pk_to_curve25519 = F.foreign (prefix^"_pk_to_curve25519")
      to_curve_25519_type
    let sign_sk_to_curve25519 = F.foreign (prefix^"_sk_to_curve25519")
      to_curve_25519_type

    module Make(T: Sodium_storage.S) = struct
      let sign_fn_type    = (T.ctype @-> ptr ullong @-> T.ctype
                             @-> ullong @-> ocaml_bytes @-> returning int)

      let sign            = F.foreign (prefix) sign_fn_type
      let sign_open       = F.foreign (prefix^"_open") sign_fn_type

      let sign_detached_type = (T.ctype @-> ptr_opt ullong @-> T.ctype
                                @-> ullong @-> ocaml_bytes @-> returning int)

      let sign_detached   = F.foreign (prefix^"_detached") sign_detached_type

      let verify_type     = (ocaml_bytes @-> T.ctype @-> ullong
                             @-> ocaml_bytes @-> returning int)

      let sign_verify     = F.foreign (prefix^"_verify_detached") verify_type
    end
  end

  module Scalar_mult = struct
    let primitive = "curve25519"
    let prefix    = "crypto_scalarmult_"^primitive

    let sz_query_type   = void @-> returning size_t
    let bytes           = F.foreign (prefix^"_bytes") sz_query_type
    let scalarbytes     = F.foreign (prefix^"_scalarbytes") sz_query_type

    let scalarmult      = F.foreign (prefix)
                                    (ocaml_bytes @-> ocaml_bytes @-> ocaml_bytes
                                     @-> returning int)
    let scalarmult_base = F.foreign (prefix^"_base")
                                    (ocaml_bytes @-> ocaml_bytes @-> returning int)
  end

  module Secret_box = struct
    let primitive = "xsalsa20poly1305"
    let prefix    = "crypto_secretbox_"^primitive

    let sz_query_type   = void @-> returning size_t
    let keybytes        = F.foreign (prefix^"_keybytes")     sz_query_type
    let noncebytes      = F.foreign (prefix^"_noncebytes")   sz_query_type
    let zerobytes       = F.foreign (prefix^"_zerobytes")    sz_query_type
    let boxzerobytes    = F.foreign (prefix^"_boxzerobytes") sz_query_type

    module Make(T: Sodium_storage.S) = struct
      let secretbox_fn_ty = (T.ctype @-> T.ctype @-> ullong
                             @-> ocaml_bytes @-> ocaml_bytes @-> returning int)

      let secretbox       = F.foreign (prefix)         secretbox_fn_ty
      let secretbox_open  = F.foreign (prefix^"_open") secretbox_fn_ty
    end
  end

  module Stream = struct
    let primitive = "xsalsa20"
    let prefix    = "crypto_stream_"^primitive

    let sz_query_type   = void @-> returning size_t
    let keybytes        = F.foreign (prefix^"_keybytes")     sz_query_type
    let noncebytes      = F.foreign (prefix^"_noncebytes")   sz_query_type

    module Make(T: Sodium_storage.S) = struct
      let stream          = F.foreign (prefix)
                                      (T.ctype @-> ullong @-> ocaml_bytes
                                       @-> ocaml_bytes @-> returning int)
      let stream_xor      = F.foreign (prefix^"_xor")
                                      (T.ctype @-> T.ctype @-> ullong
                                       @-> ocaml_bytes @-> ocaml_bytes @-> returning int)
    end
  end

  module Gen_auth(M: sig
    val scope     : string
    val primitive : string
  end) = struct
    let primitive = M.primitive
    let prefix    = "crypto_"^M.scope^"_"^primitive

    let sz_query_type = void @-> returning size_t
    let keybytes      = F.foreign (prefix^"_keybytes") sz_query_type
    let bytes         = F.foreign (prefix^"_bytes")    sz_query_type

    module Make(T: Sodium_storage.S) = struct
      let auth_fn_type  = (ocaml_bytes @-> T.ctype @-> ullong
                           @-> ocaml_bytes @-> returning int)

      let auth          = F.foreign (prefix)           auth_fn_type
      let auth_verify   = F.foreign (prefix^"_verify") auth_fn_type
    end
  end

  module Hash = struct
    let primitive = "sha512"
    let prefix    = "crypto_hash_"^primitive

    let sz_query_type = void @-> returning size_t
    let hashbytes     = F.foreign (prefix^"_bytes") sz_query_type

    module Make(T: Sodium_storage.S) = struct
      let hash          = F.foreign (prefix)
                                    (ocaml_bytes @-> T.ctype @-> ullong @-> returning int)
    end
  end

  module Generichash = struct
    let primitive = "blake2b"
    let prefix    = "crypto_generichash_"^primitive
    let sz_query_type = void @-> returning size_t

    let hashbytes     = F.foreign (prefix^"_bytes") sz_query_type
    let hashbytesmin  = F.foreign (prefix^"_bytes_min") sz_query_type
    let hashbytesmax  = F.foreign (prefix^"_bytes_max") sz_query_type

    let keybytes      = F.foreign (prefix^"_keybytes") sz_query_type
    let keybytesmin   = F.foreign (prefix^"_keybytes_min") sz_query_type
    let keybytesmax   = F.foreign (prefix^"_keybytes_max") sz_query_type

    module Make(T: Sodium_storage.S) = struct
      let hash          = F.foreign (prefix)
                          (
                              ocaml_bytes  (*  uchar * out    *)
                          @-> size_t       (*  size_t out_len *)
                          @-> T.ctype      (*  uchar * in     *)
                          @-> ullong       (*  unsigned long long in_len *)
                          @-> ocaml_bytes  (*  uchar * key    *)
                          @-> size_t       (*  size_t keylen  *)
                          @-> returning int)
    end
  end

end
