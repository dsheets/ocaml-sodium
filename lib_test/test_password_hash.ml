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

let password str =
  Password_hash.Bytes.wipe_to_password (Bytes.of_string str)

let test_derive_secret_box_keys ctxt =
  let pw  = password "Correct Horse Battery Staple" in
  let pw' = password "Correct Battery Horse Staple" in
  let n = Password_hash.random_nonce () in
  let n' = Password_hash.random_nonce () in
  let sk = Secret_box.derive_key pw (Password_hash.interactive, n) in
  let sk2 = Secret_box.derive_key pw (Password_hash.interactive, n) in
  let sk' = Secret_box.derive_key pw (Password_hash.interactive, n') in
  let sk'2 = Secret_box.derive_key pw (Password_hash.interactive, n') in
  let sk'' = Secret_box.derive_key pw (Password_hash.moderate, n) in
  let sk''2 = Secret_box.derive_key pw (Password_hash.moderate, n) in
  let sk''' = Secret_box.derive_key pw' (Password_hash.interactive, n) in
  let sk'''2 = Secret_box.derive_key pw' (Password_hash.interactive, n) in
  assert_bool "=" (Secret_box.equal_keys sk sk);
  assert_bool "=" (Secret_box.equal_keys sk sk2);
  assert_bool "=" (Secret_box.equal_keys sk' sk'2);
  assert_bool "=" (Secret_box.equal_keys sk'' sk''2);
  assert_bool "=" (Secret_box.equal_keys sk''' sk'''2);
  assert_bool "<>" (not (Secret_box.equal_keys sk sk'));
  assert_bool "<>" (not (Secret_box.equal_keys sk sk''));
  assert_bool "<>" (not (Secret_box.equal_keys sk sk'''))

let test_password_hashing ctxt =
  let pw  = password "Correct Horse Battery Staple" in
  let pw' = password "Correct Battery Horse Staple" in
  let h = Password_hash.Bytes.hash_password pw Password_hash.interactive in
  assert_bool "=" (Password_hash.Bytes.verify_password_hash pw h);
  assert_bool "<>" (not (Password_hash.Bytes.verify_password_hash pw' h))

let suite = "Password_hash" >::: [
    "test_password_hashing"             >:: test_password_hashing;
    "test_derive_secret_box_keys"       >:: test_derive_secret_box_keys;
  ]
