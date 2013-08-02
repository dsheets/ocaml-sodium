(*
 * Copyright (c) 2013 David Sheets <sheets@alum.mit.edu>
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

exception VerificationFailure
exception KeyError
exception NonceError
exception SeedError

type public
type secret
type channel (* secret *)

type octets = uchar Array.t

module Serialize = struct
  module type S = sig
    type t

    val create : int -> t
    val length : t -> int
    val of_octets : int -> octets -> t
    val into_octets : t -> int -> octets -> unit
  end

  module String : S with type t = string = struct
    type t = string

    let create = String.create

    let length = String.length

    let of_octets start b =
      let sz = Array.length b in
      let s = String.create (sz - start) in
      for i = start to (sz - 1) do
        s.[i - start] <- char_of_int (UChar.to_int b.(i));
      done; s

    let into_octets s start b = String.iteri (fun i c ->
      b.(i + start) <- UChar.of_int (int_of_char c)
    ) s
  end

  type char_bigarray = (char,
                        Bigarray.int8_unsigned_elt,
                        Bigarray.c_layout) Bigarray.Array1.t
  module Bigarray : S with type t = char_bigarray = struct
    module B = Bigarray
    type t = char_bigarray

    let create = octets_make

    let length = B.Array1.dim

    let of_octets start b =
      let sz = Array.length b in
      let s = B.Array1.create B.char B.c_layout (sz - start) in
      for i = start to (sz - 1) do
        s.{i - start} <- char_of_int (UChar.to_int b.(i));
      done; s

    let into_octets s start b =
      for i = 0 to (length s) - 1 do
        b.(i + start) <- UChar.of_int (int_of_char s.{i});
      done
  end
end

module C = struct
  open Foreign

  let init = foreign "sodium_init" (void @-> returning void)
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

  module Make(T : Serialize.S) = struct
    let random sz =
      let b = octets_make sz in
      C.gen (octets_start b) (Size_t.of_int sz);
      T.of_octets 0 b
  end
end

let wipe_octets o =
  Random.C.gen (Array.start o)
    (Size_t.of_int ((Array.length o) * (sizeof (Array.element_type o))))

let compare_octets o o' =
  let olen = Array.length o in
  let rec cmp i =
    let c = UChar.compare o.(i) o'.(i) in
    if c = 0 then let j = i+1 in if j=olen then 0 else cmp j
    else c
  in cmp 0

module Box = struct
  type 'a key  = octets
  type nonce = octets
  type ciphertext  = octets

  type sizes = {
    public_key : int;
    secret_key : int;
    beforenm   : int;
    nonce      : int;
    zero       : int;
    box_zero   : int;
  }

  let crypto_module = "crypto_box"
  let ciphersuite = "curve25519xsalsa20poly1305"

  (* TODO: alignment? *)
  module C = struct
    open Foreign
    type buffer = uchar Ctypes.ptr
    type box = buffer -> buffer -> ullong -> buffer -> buffer -> buffer -> int

    let prefix = crypto_module ^"_"^ ciphersuite
    let sz_query_type = void @-> returning size_t
    let publickeybytes = foreign (prefix^"_publickeybytes") sz_query_type
    let secretkeybytes = foreign (prefix^"_secretkeybytes") sz_query_type
    let beforenmbytes = foreign (prefix^"_beforenmbytes") sz_query_type
    let noncebytes = foreign (prefix^"_noncebytes") sz_query_type
    let zerobytes = foreign (prefix^"_zerobytes") sz_query_type
    let boxzerobytes = foreign (prefix^"_boxzerobytes") sz_query_type

    let box_keypair = foreign (prefix^"_keypair")
      (ptr uchar @-> ptr uchar @-> returning int)

    let box_fn_type = (ptr uchar @-> ptr uchar @-> ullong
                       @-> ptr uchar @-> ptr uchar @-> ptr uchar
                       @-> returning int)

    let box = foreign (prefix) box_fn_type
    let box_open = foreign (prefix^"_open") box_fn_type

    let box_afternm_type =
      (ptr uchar @-> ptr uchar @-> ullong
       @-> ptr uchar @-> ptr uchar @-> returning int)

    let box_beforenm = foreign (prefix^"_beforenm")
      (ptr uchar @-> ptr uchar @-> ptr uchar @-> returning int)
    let box_afternm = foreign (prefix^"_afternm") box_afternm_type

    let box_open_afternm = foreign (prefix^"_open_afternm") box_afternm_type
  end

  let bytes = {
    public_key=Size_t.to_int (C.publickeybytes ());
    secret_key=Size_t.to_int (C.secretkeybytes ());
    beforenm  =Size_t.to_int (C.beforenmbytes ());
    nonce     =Size_t.to_int (C.noncebytes ());
    zero      =Size_t.to_int (C.zerobytes ());
    box_zero  =Size_t.to_int (C.boxzerobytes ());
  }

  let wipe_key = wipe_octets
  let compare_keys = compare_octets

  module Make(T : Serialize.S) = struct
    let read_key sz t =
      let klen = T.length t in
      if klen <> sz then raise KeyError;
      let b = Array.make uchar klen in
      T.into_octets t 0 b;
      b
    let box_read_public_key = read_key bytes.public_key
    let box_read_secret_key = read_key bytes.secret_key
    let box_read_channel_key= read_key bytes.beforenm
    let box_write_key = T.of_octets 0

    let box_read_nonce t =
      let nlen = T.length t in
      if nlen <> bytes.nonce then raise NonceError;
      let b = Array.make uchar nlen in
      T.into_octets t 0 b;
      b
    let box_write_nonce n = T.of_octets 0 n

    let box_read_ciphertext t =
      let clen = T.length t in
      let b = Array.make uchar ~initial:UChar.zero (clen + bytes.box_zero) in
      T.into_octets t bytes.box_zero b;
      b
    let box_write_ciphertext = T.of_octets bytes.box_zero

    let box_keypair () =
      let pk = Array.make uchar bytes.public_key in
      let sk = Array.make uchar bytes.secret_key in
      let ret = C.box_keypair (Array.start pk) (Array.start sk) in
      assert (ret = 0); (* TODO: exn *)
      (pk,sk)

    let box sk pk message ~nonce =
      let mlen = T.length message + bytes.zero in
      let c = Array.make uchar mlen in
      let m = Array.make uchar ~initial:UChar.zero mlen in
      T.into_octets message bytes.zero m;
      let ret = C.box (Array.start c) (Array.start m) (ULLong.of_int mlen)
        (Array.start nonce) (Array.start pk) (Array.start sk)
      in
      assert (ret = 0); (* TODO: exn *)
      c

    let box_open sk pk crypt ~nonce =
      let clen = Array.length crypt in
      let m = Array.make uchar clen in
      let ret = C.box_open (Array.start m) (Array.start crypt)
        (ULLong.of_int clen) (Array.start nonce)
        (Array.start pk) (Array.start sk)
      in
      if ret <> 0 then raise VerificationFailure;
      T.of_octets bytes.zero m

    let box_beforenm sk pk =
      let k = Array.make uchar bytes.beforenm in
      let ret = C.box_beforenm (Array.start k) (Array.start pk)
        (Array.start sk) in
      assert (ret = 0); (* TODO: exn *)
      k

    let box_afternm k message ~nonce =
      let mlen = T.length message + bytes.zero in
      let c = Array.make uchar mlen in
      let m = Array.make uchar ~initial:UChar.zero mlen in
      T.into_octets message bytes.zero m;
      let ret = C.box_afternm (Array.start c) (Array.start m)
        (ULLong.of_int mlen) (Array.start nonce) (Array.start k)
      in
      assert (ret = 0); (* TODO: exn *)
      c

    let box_open_afternm k crypt ~nonce =
      let clen = Array.length crypt in
      let m = Array.make uchar clen in
      let ret = C.box_open_afternm (Array.start m) (Array.start crypt)
        (ULLong.of_int clen) (Array.start nonce) (Array.start k)
      in
      if ret <> 0 then raise VerificationFailure;
      T.of_octets bytes.zero m
  end
end

module Sign = struct
  type 'a key = octets

  type sizes = {
    public_key : int;
    secret_key : int;
    seed       : int;
    signature  : int;
  }

  let crypto_module = "crypto_sign"
  let ciphersuite = "ed25519"

  module C = struct
    open Foreign

    let prefix = crypto_module ^"_"^ ciphersuite
    let sz_query_type = void @-> returning size_t
    let publickeybytes = foreign (prefix^"_publickeybytes") sz_query_type
    let secretkeybytes = foreign (prefix^"_secretkeybytes") sz_query_type
    let seedbytes = foreign (prefix^"_seedbytes") sz_query_type
    let bytes = foreign (prefix^"_bytes") sz_query_type

    let sign_fn_type =
      (ptr uchar @-> ptr ullong @-> ptr uchar @-> ullong @-> ptr uchar
       @-> returning int)

    let sign_seed_keypair = foreign (prefix^"_seed_keypair")
      (ptr uchar @-> ptr uchar @-> ptr uchar @-> returning int)
    let sign_keypair = foreign (prefix^"_keypair")
      (ptr uchar @-> ptr uchar @-> returning int)
    let sign = foreign (prefix) sign_fn_type
    let sign_open = foreign (prefix^"_open") sign_fn_type
  end

  let bytes = {
    public_key = Size_t.to_int (C.publickeybytes ());
    secret_key = Size_t.to_int (C.secretkeybytes ());
    seed       = Size_t.to_int (C.seedbytes ());
    signature  = Size_t.to_int (C.bytes ());
  }

  let wipe_key = wipe_octets
  let compare_keys = compare_octets

  module Make(T : Serialize.S) = struct
    let read_key sz t =
      let klen = T.length t in
      if klen <> sz then raise KeyError;
      let b = Array.make uchar klen in
      T.into_octets t 0 b;
      b
    let sign_read_public_key = read_key bytes.public_key
    let sign_read_secret_key = read_key bytes.secret_key
    let sign_write_key = T.of_octets 0

    let sign_seed_keypair seed =
      let slen = T.length seed in
      if slen <> bytes.seed then raise SeedError;
      let b = Array.make uchar slen in
      T.into_octets seed 0 b;
      let pk = Array.make uchar bytes.public_key in
      let sk = Array.make uchar bytes.secret_key in
      let ret = C.sign_seed_keypair (Array.start pk) (Array.start sk)
        (Array.start b) in
      assert (ret = 0); (* TODO: exn *)
      (pk,sk)

    let sign_keypair () =
      let pk = Array.make uchar bytes.public_key in
      let sk = Array.make uchar bytes.secret_key in
      let ret = C.sign_keypair (Array.start pk) (Array.start sk) in
      assert (ret = 0); (* TODO: exn *)
      (pk,sk)

    let sign sk message =
      let mlen = T.length message in
      let smlen = mlen + bytes.signature in
      let psmlen = allocate ullong (ULLong.of_int 0) in
      let sm = Array.make uchar smlen in
      let m = Array.make uchar mlen in
      T.into_octets message 0 m;
      let ret = C.sign (Array.start sm) psmlen (Array.start m)
        (ULLong.of_int mlen) (Array.start sk)
      in
      assert (ret = 0); (* TODO: exn *)
      assert ((ULLong.to_int (!@ psmlen)) = smlen); (* TODO: exn *)
      T.of_octets 0 sm

    let sign_open pk smessage =
      let smlen = T.length smessage in
      let mlen = smlen - bytes.signature in
      let pmlen = allocate ullong (ULLong.of_int 0) in
      let m = Array.make uchar mlen in
      let sm = Array.make uchar smlen in
      T.into_octets smessage 0 sm;
      let ret = C.sign_open (Array.start m) pmlen (Array.start sm)
        (ULLong.of_int smlen) (Array.start pk)
      in
      assert (ret = 0); (* TODO: exn *)
      assert ((ULLong.to_int (!@ pmlen)) = mlen); (* TODO: exn *)
      T.of_octets 0 m
  end
end

module Make(T : Serialize.S) = struct
  include Random.Make(T)
  include Box.Make(T)
  include Sign.Make(T)
end
;;
C.init ()
