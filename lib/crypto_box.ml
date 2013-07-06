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
open Foreign

type octets = uchar Array.t
type public_key = octets
type secret_key = octets
type ciphertext = octets

type sizes = {
  public_key : int;
  secret_key : int;
  beforenm   : int;
  nonce      : int;
  zero       : int;
  box_zero   : int;
}

let bytes = {
  public_key=32; secret_key=32; beforenm=32; nonce=24; zero=32; box_zero=16;
}

let crypto_module = "crypto_box"
let ciphersuite = "curve25519xsalsa20poly1305"
let impl = "ref"
let prefix = Printf.sprintf "%s_%s_%s" crypto_module ciphersuite impl

let string_of_octets start k =
  let sz = Array.length k in
  let s = String.create (sz - start) in
  for i = start to (sz - 1) do
    s.[i - start] <- char_of_int (UChar.to_int (Array.get k i));
  done; s
let string_of_public_key = string_of_octets 0
let string_of_secret_key = string_of_octets 0
let string_of_ciphertext = string_of_octets 0

module C = struct
  type buffer = uchar Ctypes.ptr
  type box = buffer -> buffer -> ullong
      -> buffer -> buffer -> buffer -> int

  let keypair = foreign (prefix^"_keypair")
    (ptr uchar @-> ptr uchar @-> returning int)

  let box_fn_type = (ptr uchar @-> ptr uchar @-> ullong
                     @-> ptr uchar @-> ptr uchar @-> ptr uchar
                     @-> returning int)

  let box = foreign (prefix) box_fn_type
  let box_open = foreign (prefix^"_open") box_fn_type

  let box_afternm_type =
    (string @-> string @-> ullong @-> string @-> string @-> returning int)

  let box_beforenm_c     = foreign (prefix^"_beforenm")
    (string @-> string @-> string @-> returning int)
  let box_afternm_c      = foreign (prefix^"_afternm") box_afternm_type

  let box_open_afternm_c = foreign (prefix^"_open_afternm") box_afternm_type
end

let keypair () =
  let pk = Array.make uchar bytes.public_key in
  let sk = Array.make uchar bytes.secret_key in
  let ret = C.keypair (Array.start pk) (Array.start sk) in
  assert (ret = 0); (* TODO: exn *)
  (pk,sk)

let box sk pk message nonce =
  let mlen = String.length message + bytes.zero in
  let c = Array.make uchar mlen in
  let m = Array.make uchar ~initial:UChar.zero mlen in
  for i = bytes.zero to (mlen - 1) do
    m.(i) <- UChar.of_int (int_of_char message.[i - bytes.zero])
  done;
  let ret = C.box (Array.start c) (Array.start m) (ULLong.of_int mlen)
    (Array.start (Nonce.to_octets nonce)) (Array.start pk) (Array.start sk)
  in
  assert (ret = 0); (* TODO: exn *)
  c

let box_open sk pk crypt nonce =
  let clen = Array.length crypt in
  let m = Array.make uchar clen in
  let ret = C.box_open (Array.start m) (Array.start crypt) (ULLong.of_int clen)
    (Array.start (Nonce.to_octets nonce)) (Array.start pk) (Array.start sk)
  in
  assert (ret = 0); (* TODO: exn *)
  string_of_octets bytes.zero m

