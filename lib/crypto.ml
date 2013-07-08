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

type octets = uchar Array.t

module Serializer = struct
  module type S = sig
    type t

    val length : t -> int
    val of_octets : int -> octets -> t
    val into_octets : t -> int -> octets -> unit
  end

  module String : S with type t = string = struct
    type t = string

    let length = String.length

    let of_octets start b =
      let sz = Array.length b in
      let s = String.create (sz - start) in
      for i = start to (sz - 1) do
        s.[i - start] <- char_of_int (UChar.to_int (Array.get b i));
      done; s

    let into_octets s start b = String.iteri (fun i c ->
      b.(i + start) <- UChar.of_int (int_of_char c)
    ) s
  end
end

module Make(T : Serializer.S) = struct
  module Nonce = struct
    type t = uchar Array.t

    let zero k = Array.make uchar ~initial:UChar.zero k

    let to_octets nonce = nonce
  end

  module Box = struct
    type public_key  = octets
    type secret_key  = octets
    type channel_key = octets (* secret *)
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
    let impl = "ref"

    module C = struct
      open Foreign
      type buffer = uchar Ctypes.ptr
      type box = buffer -> buffer -> ullong -> buffer -> buffer -> buffer -> int

      let memzero = foreign "sodium_memzero"
        (ptr uchar @-> size_t @-> returning void)

      let const = Printf.sprintf "%s_%s" crypto_module ciphersuite
      let sz_query_type = void @-> returning size_t
      let publickeybytes = foreign (const^"_publickeybytes") sz_query_type
      let secretkeybytes = foreign (const^"_secretkeybytes") sz_query_type
      let beforenmbytes = foreign (const^"_beforenmbytes") sz_query_type
      let noncebytes = foreign (const^"_noncebytes") sz_query_type
      let zerobytes = foreign (const^"_zerobytes") sz_query_type
      let boxzerobytes = foreign (const^"_boxzerobytes") sz_query_type

      let prefix = Printf.sprintf "%s_%s" const impl

      let keypair = foreign (prefix^"_keypair")
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

    let wipe sk = C.memzero (Array.start sk) (Size_t.of_int (Array.length sk))

    (* TODO: alignment? *)
    let serialize_public_key = T.of_octets 0
    let serialize_secret_key = T.of_octets 0
    let serialize_channel_key= T.of_octets 0
    let serialize_ciphertext = T.of_octets 0

    let keypair () =
      let pk = Array.make uchar bytes.public_key in
      let sk = Array.make uchar bytes.secret_key in
      let ret = C.keypair (Array.start pk) (Array.start sk) in
      assert (ret = 0); (* TODO: exn *)
      (pk,sk)

    let box sk pk message ~nonce =
      let mlen = T.length message + bytes.zero in
      let c = Array.make uchar mlen in
      let m = Array.make uchar ~initial:UChar.zero mlen in
      T.into_octets message bytes.zero m;
      let ret = C.box (Array.start c) (Array.start m) (ULLong.of_int mlen)
        (Array.start (Nonce.to_octets nonce)) (Array.start pk) (Array.start sk)
      in
      assert (ret = 0); (* TODO: exn *)
      c

    let box_open sk pk crypt ~nonce =
      let clen = Array.length crypt in
      let m = Array.make uchar clen in
      let ret = C.box_open (Array.start m) (Array.start crypt)
        (ULLong.of_int clen) (Array.start (Nonce.to_octets nonce))
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
        (ULLong.of_int mlen) (Array.start (Nonce.to_octets nonce))
        (Array.start k)
      in
      assert (ret = 0); (* TODO: exn *)
      c

    let box_open_afternm k crypt ~nonce =
      let clen = Array.length crypt in
      let m = Array.make uchar clen in
      let ret = C.box_open_afternm (Array.start m) (Array.start crypt)
        (ULLong.of_int clen) (Array.start (Nonce.to_octets nonce)) (Array.start k)
      in
      if ret <> 0 then raise VerificationFailure;
      T.of_octets bytes.zero m
  end
end

