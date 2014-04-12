(*
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

open OUnit2
open Sodium

let test_equal_keys ctxt =
  let sk   = String.make (Stream.key_size) 'A' in
  let sk'  = "B" ^ (String.make (Stream.key_size - 1) 'A') in
  let sk'' = (String.make (Stream.key_size - 1) 'A') ^ "B" in
  assert_bool "=" (Stream.equal_keys (Stream.String.to_key sk)
                                         (Stream.String.to_key sk));
  assert_bool "<>" (not (Stream.equal_keys (Stream.String.to_key sk)
                                               (Stream.String.to_key sk')));
  assert_bool "<>" (not (Stream.equal_keys (Stream.String.to_key sk)
                                               (Stream.String.to_key sk'')))

let test_permute ctxt =
  let k = Stream.random_key () in
  assert_raises (Size_mismatch "Stream.to_key")
                (fun () -> (Stream.String.to_key ((Stream.String.of_key k) ^ "\x00")))

let test_nonce_operations ctxt =
  let n     = String.make Stream.nonce_size '\x00' in
  let n'    = (String.make (Stream.nonce_size - 1) '\x00') ^ "\x01" in
  let n''   = (String.make (Stream.nonce_size - 1) '\x00') ^ "\x02" in
  let n'''  = (String.make (Stream.nonce_size - 3) '\x00') ^ "\x02\x00\x00" in
  let n'''' = String.make Stream.nonce_size '\xff' in
  assert_bool "=" ((Stream.nonce_of_string n) = (Stream.nonce_of_string n));
  assert_bool "<>" ((Stream.nonce_of_string n) <> (Stream.nonce_of_string n'));
  assert_raises (Sodium.Size_mismatch "Stream.nonce_of_string")
                (fun () -> Stream.nonce_of_string (n ^ "."));
  assert_equal (Stream.nonce_of_string n')
               (Stream.increment_nonce (Stream.nonce_of_string n));
  assert_equal (Stream.nonce_of_string n'')
               (Stream.increment_nonce ~step:2 (Stream.nonce_of_string n));
  assert_equal (Stream.nonce_of_string n''')
               (Stream.increment_nonce ~step:0x20000 (Stream.nonce_of_string n));
  assert_equal (Stream.nonce_of_string n'''')
               (Stream.increment_nonce ~step:(-1) (Stream.nonce_of_string n))

let setup () =
  Stream.random_key (), "wild wild fox", Stream.random_nonce ()

let test_stream ctxt =
  let k, msg, nonce = setup () in
  let nonce' = Stream.random_nonce () in
  let cmsg  = Stream.String.stream k 10 nonce in
  let cmsg' = Stream.String.stream k 10 nonce' in
  assert_bool "not equal" (cmsg <> cmsg')

let test_stream_xor ctxt =
  let k, msg, nonce = setup () in
  let cmsg = Stream.String.stream_xor k msg nonce in
  let msg' = Stream.String.stream_xor k cmsg nonce in
  assert_equal msg msg'

let suite = "Stream" >::: [
    "test_equal_keys"       >:: test_equal_keys;
    "test_nonce_operations" >:: test_nonce_operations;
    "test_permute"          >:: test_permute;
    "test_stream"           >:: test_stream;
    "test_stream_xor"       >:: test_stream_xor;
  ]
