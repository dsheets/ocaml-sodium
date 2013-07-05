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

