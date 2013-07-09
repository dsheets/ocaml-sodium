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

open OUnit

module String_crypto = Crypto.Make(Crypto.Serializer.String)
module Crypto_box = String_crypto.Box
open Crypto_box

let drop_byte s = String.sub s 0 ((String.length s)-1)
let add_byte s = s^"\000"
let inv_byte s = s.[0] <- (char_of_int (0xff lxor (int_of_char s.[0]))); s

let right_inverse ((pk,sk),(pk',sk'),message,nonce) =
  assert_equal message (box_open sk' pk (box sk pk' message ~nonce) ~nonce)

let right_inverse_fail_sk ((pk,sk),(pk',sk'),message,nonce) =
  let perturb_sk sk fn = read_secret_key (fn (write_key sk)) in
  assert_raises Crypto.KeyError (fun () ->
    box_open (perturb_sk sk' drop_byte) pk (box sk pk' message ~nonce) ~nonce);
  assert_raises Crypto.KeyError (fun () ->
    box_open (perturb_sk sk' add_byte) pk (box sk pk' message ~nonce) ~nonce);
  assert_raises Crypto.VerificationFailure (fun () ->
    box_open (perturb_sk sk' inv_byte) pk (box sk pk' message ~nonce) ~nonce);
  ()

let right_inverse_fail_pk ((pk,sk),(pk',sk'),message,nonce) =
  let perturb_pk pk fn = read_public_key (fn (write_key sk)) in
  assert_raises Crypto.KeyError (fun () ->
    box_open sk' pk (box sk (perturb_pk pk' drop_byte) message ~nonce) ~nonce);
  assert_raises Crypto.KeyError (fun () ->
    box_open sk' pk (box sk (perturb_pk pk' add_byte) message ~nonce) ~nonce);
  assert_raises Crypto.VerificationFailure (fun () ->
    box_open sk pk (box sk (perturb_pk pk' inv_byte) message ~nonce) ~nonce);
  ()

let right_inverse_fail_ciphertext ((pk,sk),(pk',sk'),message,nonce) =
  let perturb_ciphertext ct fn = read_ciphertext (fn (write_ciphertext ct)) in
  assert_raises Crypto.VerificationFailure (fun () ->
    box_open sk' pk
      (perturb_ciphertext (box sk pk' message ~nonce) drop_byte) ~nonce);
  assert_raises Crypto.VerificationFailure (fun () ->
    box_open sk' pk
      (perturb_ciphertext (box sk pk' message ~nonce) add_byte) ~nonce);
  assert_raises Crypto.VerificationFailure (fun () ->
    box_open sk pk
      (perturb_ciphertext (box sk pk' message ~nonce) inv_byte) ~nonce);
  ()

let right_inverse_fail_nonce ((pk,sk),(pk',sk'),message,nonce) =
  let perturb_nonce n fn = read_nonce (fn (write_nonce n)) in
  assert_raises Crypto.NonceError (fun () ->
    box_open sk' pk
      (box sk pk' message ~nonce) ~nonce:(perturb_nonce nonce drop_byte));
  assert_raises Crypto.NonceError (fun () ->
    box_open sk' pk
      (box sk pk' message ~nonce) ~nonce:(perturb_nonce nonce add_byte));
  assert_raises Crypto.VerificationFailure (fun () ->
    box_open sk pk
      (box sk pk' message ~nonce) ~nonce:(perturb_nonce nonce inv_byte));
  ()

let channel_key_eq ((pk,sk),(pk',sk'),message,nonce) =
  assert_equal
    (write_key (box_beforenm sk pk'))
    (write_key (box_beforenm sk' pk))

let right_inverse_channel_key ((pk,sk),(pk',sk'),message,nonce) =
  let ck = box_beforenm sk pk' in
  let ck'= box_beforenm sk' pk in
  assert_equal
    message
    (box_open_afternm ck' (box_afternm ck message ~nonce) ~nonce)

let right_inverse_channel_key_fail ((pk,sk),(pk',sk'),message,nonce) =
  let ck = box_beforenm sk pk' in
  let ck'= box_beforenm sk' pk in
  let perturb_ciphertext ct fn = read_ciphertext (fn (write_ciphertext ct)) in 
  assert_raises Crypto.VerificationFailure (fun () ->
    box_open_afternm ck'
      (perturb_ciphertext (box_afternm ck message ~nonce) drop_byte) ~nonce);
  assert_raises Crypto.VerificationFailure (fun () ->
    box_open_afternm ck'
      (perturb_ciphertext (box_afternm ck message ~nonce) add_byte) ~nonce);
  assert_raises Crypto.VerificationFailure (fun () ->
    box_open_afternm ck'
      (perturb_ciphertext (box_afternm ck message ~nonce) inv_byte) ~nonce);
  ()

let setup _ =
  let nonce = read_nonce "012345678901234567890123" in
  (keypair (),keypair (),"The rooster crows at midnight.",nonce)

let teardown _ = ()

let suite = "Test crypto_box" >::: [
  "test_right_inverse"
  >:: (bracket setup right_inverse teardown);
  "test_right_inverse_fail_sk"
  >:: (bracket setup right_inverse_fail_sk teardown);
  "test_right_inverse_fail_pk"
  >:: (bracket setup right_inverse_fail_pk teardown);
  "test_right_inverse_fail_ciphertext"
  >:: (bracket setup right_inverse_fail_ciphertext teardown);
  "test_right_inverse_fail_nonce"
  >:: (bracket setup right_inverse_fail_nonce teardown);
  "test_channel_key_eq"
  >:: (bracket setup channel_key_eq teardown);
  "test_right_inverse_channel_key"
  >:: (bracket setup right_inverse_channel_key teardown);
  "test_right_inverse_channel_key_fail"
  >:: (bracket setup right_inverse_channel_key_fail teardown);
]

;;

run_test_tt_main suite
