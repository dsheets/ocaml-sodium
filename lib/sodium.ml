(*
 * Copyright (c) 2013 David Sheets <sheets@alum.mit.edu>
 * Copyright (c) 2014 Peter Zotov <whitequark@whitequark.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 *)

open Ctypes
open Unsigned
open PosixTypes

exception Verification_failure
exception Size_mismatch of string

type public
type secret
type channel

type bigstring = (char, Bigarray.int8_unsigned_elt, Bigarray.c_layout) Bigarray.Array1.t

module Storage = struct
  module type S = sig
    type t

    val create     : int -> t
    val zero       : t -> int -> int -> unit
    val blit       : t -> int -> t -> int -> int -> unit
    val sub        : t -> int -> int -> t
    val length     : t -> int
    val len_size_t : t -> size_t
    val len_ullong : t -> ullong
    val to_ptr     : t -> uchar ptr
    val to_string  : t -> string
    val of_string  : string -> t
  end

  let coerce_char_uchar = coerce (ptr char) (ptr uchar)

  module Bigstring : S with type t = bigstring = struct
    open Bigarray

    type t = bigstring

    let create     len = (Array1.create char c_layout len)
    let length     str = Array1.dim str
    let len_size_t str = Unsigned.Size_t.of_int (Array1.dim str)
    let len_ullong str = Unsigned.ULLong.of_int (Array1.dim str)
    let to_ptr     str = coerce_char_uchar (bigarray_start array1 str)
    let zero       str pos len = (Array1.fill (Array1.sub str pos len) '\x00')

    let to_string  str =
      let str' = String.create (Array1.dim str) in
      String.iteri (fun i _ -> str'.[i] <- Array1.unsafe_get str i) str';
      str'

    let of_string  str =
      let str' = create (String.length str) in
      String.iteri (Array1.unsafe_set str') str;
      str'

    let sub = Array1.sub

    let blit src srcoff dst dstoff len =
      Array1.blit (Array1.sub src srcoff len)
                  (Array1.sub dst dstoff len)
  end

  module String : S with type t = string = struct
    type t = string

    let create     len = String.create len
    let length     str = String.length str
    let len_size_t str = Unsigned.Size_t.of_int (String.length str)
    let len_ullong str = Unsigned.ULLong.of_int (String.length str)
    let to_ptr     str = coerce_char_uchar (string_start str)
    let zero       str pos len = String.fill str pos len '\x00'
    let to_string  str = str
    let of_string  str = str
    let sub            = String.sub
    let blit           = String.blit
  end
end

module C = struct
  open Foreign

  let prefix = "sodium"

  let init    = foreign (prefix^"_init")    (void @-> returning void)
  let memzero = foreign (prefix^"_memzero") (ptr void @-> size_t @-> returning void)
  let memcmp  = foreign (prefix^"_memcmp")  (ptr void @-> ptr void @-> size_t @-> returning void)
end

let wipe str =
  C.memzero (to_voidp (Storage.String.to_ptr str)) (Storage.String.len_size_t str)

let increment_be_string ?(step=1) s =
  let s = String.copy s in
  let rec incr_byte step byteno =
    let res    = (Char.code s.[byteno]) + step in
    let lo, hi = res land 0xff, res asr 8 in
    s.[byteno] <- Char.chr lo;
    if hi = 0 || byteno = 0 then ()
    else incr_byte hi (byteno - 1)
  in
  incr_byte step ((String.length s) - 1);
  s

module Verify = struct
  module C = struct
    open Foreign

    let prefix      = "crypto_verify"

    let verify_type = ptr uchar @-> ptr uchar @-> returning int
    let verify_16   = foreign (prefix^"_16") verify_type
    let verify_32   = foreign (prefix^"_32") verify_type
    (* TODO need newer libsodium *)
    (* let verify_64   = foreign (prefix^"_64") verify_type *)
  end

  let equal_fn size =
    match size with
    | 16 -> fun a b -> (C.verify_16 (Storage.String.to_ptr a)
                                    (Storage.String.to_ptr b)) = 0
    | 32 -> fun a b -> (C.verify_32 (Storage.String.to_ptr a)
                                    (Storage.String.to_ptr b)) = 0
    (* | 64 -> fun a b -> (C.verify_64 (Storage.String.to_ptr a)
                                    (Storage.String.to_ptr b)) = 0 *)
    | 64 -> fun a b -> ((C.verify_32 (Storage.String.to_ptr a)
                                     (Storage.String.to_ptr b)) lor
                        (C.verify_32 ((Storage.String.to_ptr a) +@ 32)
                                     ((Storage.String.to_ptr b) +@ 32))) = 0
    | _ -> assert false
end

module Random = struct
  (* TODO: support changing generator *)
  module C = struct
    open Foreign
    let stir = foreign "randombytes_stir" (void @-> returning void)
    let gen  = foreign "randombytes_buf"
      (ptr uchar @-> size_t @-> returning void)
  end

  let stir = C.stir

  module type S = sig
    type storage
    val generate_into : storage -> unit
    val generate      : int -> storage
  end

  module Make(T: Storage.S) = struct
    type storage = T.t

    let generate_into str =
      C.gen (T.to_ptr str) (T.len_size_t str)

    let generate size =
      let str = T.create size in
      generate_into str;
      str
  end

  module String = Make(Storage.String)
  module Bigstring = Make(Storage.Bigstring)
end

module Box = struct
  let primitive = "curve25519xsalsa20poly1305"

  module C = struct
    open Foreign

    let prefix = "crypto_box_"^primitive

    let sz_query_type    = void @-> returning size_t
    let publickeybytes   = foreign (prefix^"_publickeybytes") sz_query_type
    let secretkeybytes   = foreign (prefix^"_secretkeybytes") sz_query_type
    let beforenmbytes    = foreign (prefix^"_beforenmbytes")  sz_query_type
    let noncebytes       = foreign (prefix^"_noncebytes")     sz_query_type
    let zerobytes        = foreign (prefix^"_zerobytes")      sz_query_type
    let boxzerobytes     = foreign (prefix^"_boxzerobytes")   sz_query_type

    let box_keypair      = foreign (prefix^"_keypair")
                                   (ptr uchar @-> ptr uchar @-> returning int)

    let box_fn_type      = (ptr uchar @-> ptr uchar @-> ullong
                            @-> ptr uchar @-> ptr uchar @-> ptr uchar
                            @-> returning int)

    let box              = foreign (prefix) box_fn_type
    let box_open         = foreign (prefix^"_open") box_fn_type

    let box_beforenm     = foreign (prefix^"_beforenm")
                                   (ptr uchar @-> ptr uchar @-> ptr uchar @-> returning int)

    let box_afternm_type = (ptr uchar @-> ptr uchar @-> ullong
                            @-> ptr uchar @-> ptr uchar @-> returning int)

    let box_afternm      = foreign (prefix^"_afternm") box_afternm_type
    let box_open_afternm = foreign (prefix^"_open_afternm") box_afternm_type
  end

  let public_key_size  = Size_t.to_int (C.publickeybytes ())
  let secret_key_size  = Size_t.to_int (C.secretkeybytes ())
  let channel_key_size = Size_t.to_int (C.beforenmbytes ())
  let nonce_size       = Size_t.to_int (C.noncebytes ())
  let zero_size        = Size_t.to_int (C.zerobytes ())
  let box_zero_size    = Size_t.to_int (C.boxzerobytes ())

  (* Invariant: a key is {public,secret,channel}_key_size bytes long. *)
  type 'a key = string
  type keypair = secret key * public key

  (* Invariant: a nonce is nonce_size bytes long. *)
  type nonce = string

  let random_keypair () =
    let pk, sk = String.create public_key_size,
                 String.create secret_key_size in
    let ret = C.box_keypair (Storage.String.to_ptr pk) (Storage.String.to_ptr sk) in
    assert (ret = 0); (* always returns 0 *)
    sk, pk

  let random_nonce () =
    Random.String.generate nonce_size

  let wipe_key = wipe

  let equal_public_keys = Verify.equal_fn public_key_size
  let equal_secret_keys = Verify.equal_fn secret_key_size
  let equal_channel_keys = Verify.equal_fn channel_key_size
  let compare_public_keys = String.compare

  let nonce_of_string s =
    if String.length s <> nonce_size then
      raise (Size_mismatch "Box.nonce_of_string");
    s

  let increment_nonce = increment_be_string

  let precompute skey pkey =
    let params = String.create channel_key_size in
    let ret = C.box_beforenm (Storage.String.to_ptr params)
                             (Storage.String.to_ptr pkey)
                             (Storage.String.to_ptr skey) in
    assert (ret = 0); (* always returns 0 *)
    params

  module type S = sig
    type storage

    val of_public_key   : public key -> storage
    val to_public_key   : storage -> public key

    val of_secret_key   : secret key -> storage
    val to_secret_key   : storage -> secret key

    val of_channel_key  : channel key -> storage
    val to_channel_key  : storage -> channel key

    val of_nonce        : nonce -> storage
    val to_nonce        : storage -> nonce

    val box             : secret key -> public key -> storage -> nonce -> storage
    val box_open        : secret key -> public key -> storage -> nonce -> storage

    val fast_box        : channel key -> storage -> nonce -> storage
    val fast_box_open   : channel key -> storage -> nonce -> storage
  end

  module Make(T: Storage.S) = struct
    type storage = T.t

    let verify_length str len fn_name =
      if T.length str <> len then raise (Size_mismatch fn_name)

    let of_public_key key =
      T.of_string key

    let to_public_key str =
      verify_length str public_key_size "Box.to_public_key";
      T.to_string str

    let of_secret_key key =
      T.of_string key

    let to_secret_key str =
      verify_length str secret_key_size "Box.to_secret_key";
      T.to_string str

    let of_channel_key key =
      T.of_string key

    let to_channel_key str =
      verify_length str channel_key_size "Box.to_channel_key";
      T.to_string str

    let of_nonce nonce =
      T.of_string nonce

    let to_nonce str =
      verify_length str nonce_size "Box.to_nonce";
      T.to_string str

    let pad a apad bpad f =
      let a' = T.create (apad + T.length a) in
      let b' = T.create (T.length a') in
      T.zero a' 0 apad;
      T.blit a  0 a' apad (T.length a);
      f a' b';
      T.sub b' bpad ((T.length b') - bpad)

    let box skey pkey message nonce =
      pad message zero_size box_zero_size (fun cleartext ciphertext ->
        let ret = C.box (T.to_ptr ciphertext) (T.to_ptr cleartext)
                        (T.len_ullong cleartext)
                        (Storage.String.to_ptr nonce)
                        (Storage.String.to_ptr pkey) (Storage.String.to_ptr skey) in
        assert (ret = 0) (* always returns 0 *))

    let box_open skey pkey ciphertext nonce =
      pad ciphertext box_zero_size zero_size (fun ciphertext cleartext ->
        let ret = C.box_open (T.to_ptr cleartext) (T.to_ptr ciphertext)
                             (T.len_ullong ciphertext)
                             (Storage.String.to_ptr nonce)
                             (Storage.String.to_ptr pkey) (Storage.String.to_ptr skey) in
        if ret <> 0 then raise Verification_failure)

    let fast_box params message nonce =
      pad message zero_size box_zero_size (fun cleartext ciphertext ->
        let ret = C.box_afternm (T.to_ptr ciphertext) (T.to_ptr cleartext)
                                (T.len_ullong cleartext)
                                (Storage.String.to_ptr nonce)
                                (Storage.String.to_ptr params) in
        assert (ret = 0) (* always returns 0 *))

    let fast_box_open params ciphertext nonce =
      pad ciphertext box_zero_size zero_size (fun ciphertext cleartext ->
        let ret = C.box_open_afternm (T.to_ptr cleartext) (T.to_ptr ciphertext)
                                     (T.len_ullong ciphertext)
                                     (Storage.String.to_ptr nonce)
                                     (Storage.String.to_ptr params) in
        if ret <> 0 then raise Verification_failure)
  end

  module String = Make(Storage.String)
  module Bigstring = Make(Storage.Bigstring)
end

module Sign = struct
  let primitive = "ed25519"

  module C = struct
    open Foreign

    let prefix = "crypto_sign_"^primitive

    let sz_query_type   = void @-> returning size_t
    let publickeybytes  = foreign (prefix^"_publickeybytes") sz_query_type
    let secretkeybytes  = foreign (prefix^"_secretkeybytes") sz_query_type
    let bytes           = foreign (prefix^"_bytes")          sz_query_type

    let sign_keypair    = foreign (prefix^"_keypair")
                                  (ptr uchar @-> ptr uchar @-> returning int)

    let sign_fn_type    = (ptr uchar @-> ptr ullong @-> ptr uchar
                           @-> ullong @-> ptr uchar @-> returning int)

    let sign            = foreign (prefix) sign_fn_type
    let sign_open       = foreign (prefix^"_open") sign_fn_type
  end

  let public_key_size  = Size_t.to_int (C.publickeybytes ())
  let secret_key_size  = Size_t.to_int (C.secretkeybytes ())
  let reserved_size    = Size_t.to_int (C.bytes ())

  (* Invariant: a key is {public,secret}_key_size bytes long. *)
  type 'a key = string
  type keypair = secret key * public key

  let random_keypair () =
    let pk, sk = String.create public_key_size,
                 String.create secret_key_size in
    let ret = C.sign_keypair (Storage.String.to_ptr pk) (Storage.String.to_ptr sk) in
    assert (ret = 0); (* always returns 0 *)
    sk, pk

  let wipe_key = wipe

  let equal_public_keys = Verify.equal_fn public_key_size
  let equal_secret_keys = Verify.equal_fn secret_key_size
  let compare_public_keys = String.compare

  module type S = sig
    type storage

    val of_public_key   : public key -> storage
    val to_public_key   : storage -> public key

    val of_secret_key   : secret key -> storage
    val to_secret_key   : storage -> secret key

    val sign            : secret key -> storage -> storage
    val sign_open       : public key -> storage -> storage
  end

  module Make(T: Storage.S) = struct
    type storage = T.t

    let verify_length str len fn_name =
      if T.length str <> len then raise (Size_mismatch fn_name)

    let of_public_key key =
      T.of_string key

    let to_public_key str =
      verify_length str public_key_size "Sign.to_public_key";
      T.to_string str

    let of_secret_key key =
      T.of_string key

    let to_secret_key str =
      verify_length str secret_key_size "Sign.to_secret_key";
      T.to_string str

    let sign skey message =
      let signed_msg = T.create ((T.length message) + reserved_size) in
      let signed_len = allocate ullong (Unsigned.ULLong.of_int 0) in
      let ret = C.sign (T.to_ptr signed_msg) signed_len
                       (T.to_ptr message) (T.len_ullong message)
                       (Storage.String.to_ptr skey) in
      assert (ret = 0); (* always returns 0 *)
      T.sub signed_msg 0 (Unsigned.ULLong.to_int (!@ signed_len))

    let sign_open pkey signed_msg =
      let message = T.create (T.length signed_msg) in
      let msg_len = allocate ullong (Unsigned.ULLong.of_int 0) in
      let ret = C.sign_open (T.to_ptr message) msg_len
                            (T.to_ptr signed_msg) (T.len_ullong signed_msg)
                            (Storage.String.to_ptr pkey) in
      if ret <> 0 then raise Verification_failure;
      T.sub message 0 (Unsigned.ULLong.to_int (!@ msg_len))
  end

  module String = Make(Storage.String)
  module Bigstring = Make(Storage.Bigstring)
end

module Scalar_mult = struct
  let primitive = "curve25519"

  module C = struct
    open Foreign

    let prefix          = "crypto_scalarmult_"^primitive

    let sz_query_type   = void @-> returning size_t
    let bytes           = foreign (prefix^"_bytes") sz_query_type
    let scalarbytes     = foreign (prefix^"_scalarbytes") sz_query_type

    let scalarmult      = foreign (prefix)
                                  (ptr uchar @-> ptr uchar @-> ptr uchar @-> returning int)
    let scalarmult_base = foreign (prefix^"_base")
                                  (ptr uchar @-> ptr uchar @-> returning int)
  end

  let group_elt_size = Size_t.to_int (C.bytes ())
  let integer_size   = Size_t.to_int (C.scalarbytes ())

  (* Invariant: a group element is group_elt_size bytes long. *)
  type group_elt = string

  (* Invariant: an integer is integer_size bytes long. *)
  type integer = string

  let equal_group_elt = Verify.equal_fn group_elt_size
  let equal_integer = Verify.equal_fn integer_size

  let mult scalar elem =
    let elem' = Storage.String.create group_elt_size in
    let ret   = Storage.String.(C.scalarmult (to_ptr elem') (to_ptr scalar)
                                             (to_ptr elem)) in
    assert (ret = 0); (* always returns 0 *)
    elem'

  let base scalar =
    let elem = Storage.String.create group_elt_size in
    let ret  = Storage.String.(C.scalarmult_base (to_ptr elem) (to_ptr scalar)) in
    assert (ret = 0); (* always returns 0 *)
    elem

  module type S = sig
    type storage

    val of_group_elt  : group_elt -> storage
    val to_group_elt  : storage -> group_elt

    val of_integer    : integer -> storage
    val to_integer    : storage -> integer
  end

  module Make(T: Storage.S) = struct
    type storage = T.t

    let of_group_elt str =
      T.of_string str

    let to_group_elt str =
      if T.length str <> group_elt_size then
        raise (Size_mismatch "Scalar_mult.to_group_elt");
      T.to_string str

    let of_integer str =
      T.of_string str

    let to_integer str =
      if T.length str <> integer_size then
        raise (Size_mismatch "Scalar_mult.to_integer");
      T.to_string str
  end

  module String = Make(Storage.String)
  module Bigstring = Make(Storage.Bigstring)
end

module Secret_box = struct
  let primitive = "xsalsa20poly1305"

  module C = struct
    open Foreign

    let prefix = "crypto_secretbox_"^primitive

    let sz_query_type   = void @-> returning size_t
    let keybytes        = foreign (prefix^"_keybytes")     sz_query_type
    let noncebytes      = foreign (prefix^"_noncebytes")   sz_query_type
    let zerobytes       = foreign (prefix^"_zerobytes")    sz_query_type
    let boxzerobytes    = foreign (prefix^"_boxzerobytes") sz_query_type

    let secretbox_fn_ty = (ptr uchar @-> ptr uchar @-> ullong
                           @-> ptr uchar @-> ptr uchar @-> returning int)

    let secretbox       = foreign (prefix)         secretbox_fn_ty
    let secretbox_open  = foreign (prefix^"_open") secretbox_fn_ty
  end

  let key_size      = Size_t.to_int (C.keybytes ())
  let nonce_size    = Size_t.to_int (C.noncebytes ())
  let zero_size     = Size_t.to_int (C.zerobytes ())
  let box_zero_size = Size_t.to_int (C.boxzerobytes ())

  (* Invariant: a key is key_size bytes long. *)
  type 'a key = string

  (* Invariant: a nonce is nonce_size bytes long. *)
  type nonce = string

  let random_key () =
    Random.String.generate key_size

  let random_nonce =
    if nonce_size > 8 then
      fun () -> Random.String.generate nonce_size
    else
      fun () -> raise (Failure "Randomly generated nonces 8 bytes long or less are unsafe")

  let nonce_of_string s =
    if String.length s <> nonce_size then
      raise (Size_mismatch "Secret_box.nonce_of_string");
    s

  let increment_nonce = increment_be_string

  let wipe_key = wipe

  let equal_keys = Verify.equal_fn key_size

  module type S = sig
    type storage

    val of_key          : secret key -> storage
    val to_key          : storage -> secret key

    val of_nonce        : nonce -> storage
    val to_nonce        : storage -> nonce

    val secret_box      : secret key -> storage -> nonce -> storage
    val secret_box_open : secret key -> storage -> nonce -> storage
  end

  module Make(T: Storage.S) = struct
    type storage = T.t

    let verify_length str len fn_name =
      if T.length str <> len then raise (Size_mismatch fn_name)

    let of_key key =
      T.of_string key

    let to_key str =
      verify_length str key_size "Secret_box.to_key";
      T.to_string str

    let of_nonce nonce =
      T.of_string nonce

    let to_nonce str =
      verify_length str nonce_size "Secret_box.to_nonce";
      T.to_string str

    let pad a apad bpad f =
      let a' = T.create (apad + T.length a) in
      let b' = T.create (T.length a') in
      T.zero a' 0 apad;
      T.blit a  0 a' apad (T.length a);
      f a' b';
      T.sub b' bpad ((T.length b') - bpad)

    let secret_box key message nonce =
      pad message zero_size box_zero_size (fun cleartext ciphertext ->
        let ret = C.secretbox (T.to_ptr ciphertext) (T.to_ptr cleartext)
                              (T.len_ullong cleartext)
                              (Storage.String.to_ptr nonce)
                              (Storage.String.to_ptr key) in
        assert (ret = 0) (* always returns 0 *))

    let secret_box_open key ciphertext nonce =
      pad ciphertext box_zero_size zero_size (fun ciphertext cleartext ->
        let ret = C.secretbox_open (T.to_ptr cleartext) (T.to_ptr ciphertext)
                                   (T.len_ullong ciphertext)
                                   (Storage.String.to_ptr nonce)
                                   (Storage.String.to_ptr key) in
        if ret <> 0 then raise Verification_failure)
  end

  module String = Make(Storage.String)
  module Bigstring = Make(Storage.Bigstring)
end

module Stream = struct
  let primitive = "xsalsa20"

  module C = struct
    open Foreign

    let prefix = "crypto_stream_"^primitive

    let sz_query_type   = void @-> returning size_t
    let keybytes        = foreign (prefix^"_keybytes")     sz_query_type
    let noncebytes      = foreign (prefix^"_noncebytes")   sz_query_type

    let stream          = foreign (prefix)
                                  (ptr uchar @-> ullong @-> ptr uchar
                                   @-> ptr uchar @-> returning int)
    let stream_xor      = foreign (prefix^"_xor")
                                  (ptr uchar @-> ptr uchar @-> ullong
                                   @-> ptr uchar @-> ptr uchar @-> returning int)
  end

  let key_size      = Size_t.to_int (C.keybytes ())
  let nonce_size    = Size_t.to_int (C.noncebytes ())

  (* Invariant: a key is key_size bytes long. *)
  type 'a key = string

  (* Invariant: a nonce is nonce_size bytes long. *)
  type nonce = string

  let random_key () =
    Random.String.generate key_size

  let random_nonce =
    if nonce_size > 8 then
      fun () -> Random.String.generate nonce_size
    else
      fun () -> raise (Failure "Randomly generated nonces 8 bytes long or less are unsafe")

  let nonce_of_string s =
    if String.length s <> nonce_size then
      raise (Size_mismatch "Stream.nonce_of_string");
    s

  let increment_nonce = increment_be_string

  let wipe_key = wipe

  let equal_keys = Verify.equal_fn key_size

  module type S = sig
    type storage

    val of_key     : secret key -> storage
    val to_key     : storage -> secret key

    val of_nonce   : nonce -> storage
    val to_nonce   : storage -> nonce

    val stream     : secret key -> int -> nonce -> storage
    val stream_xor : secret key -> storage -> nonce -> storage
  end

  module Make(T: Storage.S) = struct
    type storage = T.t

    let verify_length str len fn_name =
      if T.length str <> len then raise (Size_mismatch fn_name)

    let of_key key =
      T.of_string key

    let to_key str =
      verify_length str key_size "Stream.to_key";
      T.to_string str

    let of_nonce nonce =
      T.of_string nonce

    let to_nonce str =
      verify_length str nonce_size "Stream.to_nonce";
      T.to_string str

    let stream key len nonce =
      let stream = T.create len in
      let ret = C.stream (T.to_ptr stream) (T.len_ullong stream)
                         (Storage.String.to_ptr nonce)
                         (Storage.String.to_ptr key) in
      assert (ret = 0); (* always returns 0 *)
      stream

    let stream_xor key message nonce =
      let ciphertext = T.create (T.length message) in
      let ret = C.stream_xor (T.to_ptr ciphertext)
                             (T.to_ptr message) (T.len_ullong message)
                             (Storage.String.to_ptr nonce)
                             (Storage.String.to_ptr key) in
      assert (ret = 0); (* always returns 0 *)
      ciphertext
  end

  module String = Make(Storage.String)
  module Bigstring = Make(Storage.Bigstring)
end

module Hash = struct
  let primitive = "sha512"

  module C = struct
    open Foreign

    let prefix        = "crypto_hash_"^primitive

    let sz_query_type = void @-> returning size_t
    let hashbytes     = foreign (prefix^"_bytes") sz_query_type

    let hash          = foreign (prefix)
                                (ptr uchar @-> ptr uchar @-> ullong @-> returning int)
  end

  let size = Size_t.to_int (C.hashbytes ())

  (* Invariant: a hash is size bytes long. *)
  type hash = string

  let equal = Verify.equal_fn size

  module type S = sig
    type storage

    val of_hash : hash -> storage
    val to_hash : storage -> hash

    val digest  : storage -> hash
  end

  module Make(T: Storage.S) = struct
    type storage = T.t

    let of_hash str =
      T.of_string str

    let to_hash str =
      if T.length str <> size then
        raise (Size_mismatch "Hash.to_hash");
      T.to_string str

    let digest str =
      let hash = Storage.String.create size in
      let ret = C.hash (Storage.String.to_ptr hash) (T.to_ptr str) (T.len_ullong str) in
      assert (ret = 0); (* always returns 0 *)
      hash
  end

  module String = Make(Storage.String)
  module Bigstring = Make(Storage.Bigstring)
end

let () =
  C.init ()
