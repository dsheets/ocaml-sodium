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

type public_key = UChar.t Array.t
type secret_key = UChar.t Array.t

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

let string_of_key sz k =
  let s = String.create sz in
  for i = 0 to (sz - 1) do
    s.[i] <- char_of_int (UChar.to_int (Array.get k i));
  done; s
let string_of_public_key = string_of_key bytes.public_key
let string_of_secret_key = string_of_key bytes.secret_key

let box_fn_type = (string @-> string @-> ullong
                   @-> string @-> string @-> string
                   @-> returning int)

let box_afternm_type =
  (string @-> string @-> ullong @-> string @-> string @-> returning int)

let box_c              = foreign (prefix) box_fn_type
let box_open_c         = foreign (prefix^"_open") box_fn_type

module C = struct
  let keypair = foreign (prefix^"_keypair")
    (ptr uchar @-> ptr uchar @-> returning int)
end
let keypair () =
  let pk = Array.make uchar bytes.public_key in
  let sk = Array.make uchar bytes.secret_key in
  let ret = C.keypair (Array.start pk) (Array.start sk) in
  assert (ret = 0); (* TODO: exn *)
  (pk,sk)

let box_beforenm_c     = foreign (prefix^"_beforenm")
  (string @-> string @-> string @-> returning int)
let box_afternm_c      = foreign (prefix^"_afternm") box_afternm_type

let box_open_afternm_c = foreign (prefix^"_open_afternm") box_afternm_type

