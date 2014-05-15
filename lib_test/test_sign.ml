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

let add_byte b = Bytes.concat (Bytes.of_string "") [b; Bytes.of_string "\x00"]

let test_equal_public_keys ctxt =
  let pk   = Bytes.of_string (String.make (Sign.public_key_size) 'A') in
  let pk'  = Bytes.of_string ("B" ^ (String.make (Sign.public_key_size - 1) 'A')) in
  let pk'' = Bytes.of_string ((String.make (Sign.public_key_size - 1) 'A') ^ "B") in
  assert_bool "=" (Sign.equal_public_keys (Sign.Bytes.to_public_key pk)
                                          (Sign.Bytes.to_public_key pk));
  assert_bool "<>" (not (Sign.equal_public_keys (Sign.Bytes.to_public_key pk)
                                                (Sign.Bytes.to_public_key pk')));
  assert_bool "<>" (not (Sign.equal_public_keys (Sign.Bytes.to_public_key pk)
                                                (Sign.Bytes.to_public_key pk'')))

let test_equal_secret_keys ctxt =
  let sk   = Bytes.of_string (String.make (Sign.secret_key_size) 'A') in
  let sk'  = Bytes.of_string ("B" ^ (String.make (Sign.secret_key_size - 1) 'A')) in
  let sk'' = Bytes.of_string ((String.make (Sign.secret_key_size - 1) 'A') ^ "B") in
  assert_bool "=" (Sign.equal_secret_keys (Sign.Bytes.to_secret_key sk)
                                          (Sign.Bytes.to_secret_key sk));
  assert_bool "<>" (not (Sign.equal_secret_keys (Sign.Bytes.to_secret_key sk)
                                                (Sign.Bytes.to_secret_key sk')));
  assert_bool "<>" (not (Sign.equal_secret_keys (Sign.Bytes.to_secret_key sk)
                                                (Sign.Bytes.to_secret_key sk'')))

let test_compare_public_keys ctxt =
  let pk   = Bytes.of_string (String.make (Sign.public_key_size) 'A') in
  let pk'  = Bytes.of_string ((String.make (Sign.public_key_size - 1) 'A') ^ "0") in
  let pk'' = Bytes.of_string ("B" ^ (String.make (Sign.public_key_size - 1) 'A')) in
  assert_equal 0    (Sign.compare_public_keys (Sign.Bytes.to_public_key pk)
                                    (Sign.Bytes.to_public_key pk));
  assert_equal 1    (Sign.compare_public_keys (Sign.Bytes.to_public_key pk)
                                    (Sign.Bytes.to_public_key pk'));
  assert_equal (-1) (Sign.compare_public_keys (Sign.Bytes.to_public_key pk)
                                    (Sign.Bytes.to_public_key pk''));
  ()

let test_permute ctxt =
  let (sk, pk) = Sign.random_key_pair () in
  assert_raises (Size_mismatch "Sign.to_public_key")
                (fun () -> (Sign.Bytes.to_public_key (add_byte (Sign.Bytes.of_public_key pk))));
  assert_raises (Size_mismatch "Sign.to_secret_key")
                (fun () -> (Sign.Bytes.to_secret_key (add_byte (Sign.Bytes.of_secret_key sk))))

let setup () =
  Sign.random_key_pair (), Bytes.of_string "fuwa-fuwa-fuwa"

let test_sign ctxt =
  let (sk, pk), msg = setup () in
  let smsg = Sign.Bytes.sign sk msg in
  let msg' = Sign.Bytes.sign_open pk smsg in
  assert_equal msg msg'

let test_sign_fail_permute ctxt =
  let (sk, pk), msg = setup () in
  let smsg = Sign.Bytes.sign sk msg in
  Bytes.set smsg 10 'a';
  assert_raises Verification_failure
                (fun () -> ignore (Sign.Bytes.sign_open pk smsg))

let test_sign_fail_key ctxt =
  let (sk, pk), msg = setup () in
  let (sk',pk') = Sign.random_key_pair () in
  let smsg = Sign.Bytes.sign sk msg in
  assert_raises Verification_failure
                (fun () -> ignore (Sign.Bytes.sign_open pk' smsg))

let suite = "Sign" >::: [
    "test_equal_public_keys"   >:: test_equal_public_keys;
    "test_equal_secret_keys"   >:: test_equal_secret_keys;
    "test_compare_public_keys" >:: test_compare_public_keys;
    "test_permute"             >:: test_permute;
    "test_sign"                >:: test_sign;
    "test_sign_fail_permute"   >:: test_sign_fail_permute;
    "test_sign_fail_key"       >:: test_sign_fail_key;
  ]
