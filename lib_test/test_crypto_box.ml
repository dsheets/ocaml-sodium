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

let setup _ =
  let nonce = read_nonce "012345678901234567890123" in
  (keypair (),keypair (),"The rooster crows at midnight.",nonce)

let teardown _ = ()

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
    box_open sk' pk (box sk (perturb_pk pk' inv_byte) message ~nonce) ~nonce);
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
    box_open sk' pk
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
    box_open sk' pk
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

let invariants = "invariants" >::: [
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

let effective_wipe ((pk,sk),(pk',sk'),message,nonce) =
  let ct = box sk pk' message ~nonce in
  assert_equal message (box_open sk' pk ct ~nonce);
  wipe sk';
  assert_raises Crypto.VerificationFailure (fun () ->
    assert (message = (box_open sk' pk ct ~nonce))
  );
  ()

let compare_keys_eq ((pk,sk),(pk',sk'),message,nonce) =
  let ck = box_beforenm sk pk' in
  let ck' = box_beforenm sk' pk in
  let ck_0 = box_beforenm sk pk in
  let ck_1 = box_beforenm sk' pk' in
  let neq_msg = "different keys shouldn't be equal" in
  assert_equal 0 (compare_keys pk pk);
  assert_equal 0 (compare_keys pk' pk');
  assert_equal 0 (compare_keys sk sk);
  assert_equal 0 (compare_keys sk' sk');
  assert_equal 0 (compare_keys ck ck);
  assert_equal 0 (compare_keys ck' ck');
  assert_equal 0 (compare_keys ck ck');
  assert_bool neq_msg (0 <> (compare_keys pk pk'));
  assert_bool neq_msg (0 <> (compare_keys sk sk'));
  assert_bool neq_msg (0 <> (compare_keys ck ck_0));
  assert_bool neq_msg (0 <> (compare_keys ck ck_1));
  assert_bool neq_msg (0 <> (compare_keys ck_0 ck_1));
  ()

let compare_keys_trans ((pk,sk),(pk',sk'),message,nonce) =
  let (pk'',sk'') = keypair () in
  let pks = List.sort compare_keys [pk;pk';pk''] in
  let sks = List.sort compare_keys [sk;sk';sk''] in
  let check_trans = function
    | [a;b;c] ->
        assert_equal 1 (compare_keys c b);
        assert_equal 1 (compare_keys b a);
        assert_equal 1 (compare_keys c a);
    | _ -> assert_failure "broken test"
  in
  check_trans pks;
  check_trans sks;
  ()

let convenience = "convenience" >::: [
  "test_wipe"
  >:: (bracket setup effective_wipe teardown);
  "test_compare_keys_eq"
  >:: (bracket setup compare_keys_eq teardown);
  "test_compare_keys_trans"
  >:: (bracket setup compare_keys_trans teardown);
]

let rec hex_of_str = function
  | "" -> ""
  | s -> (Printf.sprintf "%02x" (int_of_char s.[0]))
      ^(hex_of_str (String.sub s 1 ((String.length s) - 1)))

let rec str_of_hex = function
  | "" -> ""
  | h -> Scanf.sscanf h "%2x"
      (fun i -> (String.make 1 (char_of_int i))
        ^(str_of_hex (String.sub h 2 ((String.length h) - 2))))

let str_of_stream s =
  let rec read p =
    try read (p^(String.make 1 (Stream.next s)))
    with Stream.Failure -> p
  in read ""

let check_nacl v out = assert_equal (str_of_hex (str_of_stream out)) v

let pynacl_test = "lib_test/pynacl_test.py"
let pynacl_box ((pk,sk),(pk',sk'),message,nonce) =
  assert_command
    ~foutput:(check_nacl (write_ciphertext (box sk' pk message ~nonce)))
    pynacl_test
    ["-f"; "box";
     hex_of_str message; hex_of_str (write_nonce nonce);
     hex_of_str (write_key pk); hex_of_str (write_key sk')]

let pynacl_box_open ((pk,sk),(pk',sk'),message,nonce) =
  let c = box sk' pk message ~nonce in
  assert_command
    ~foutput:(check_nacl (box_open sk pk' c ~nonce))
    pynacl_test
    ["-f"; "box_open";
     hex_of_str (write_ciphertext c); hex_of_str (write_nonce nonce);
     hex_of_str (write_key pk'); hex_of_str (write_key sk)]

let pynacl_box_beforenm ((pk,sk),(pk',sk'),message,nonce) =
  assert_command
    ~foutput:(check_nacl (write_key (box_beforenm sk' pk)))
    pynacl_test
    ["-f"; "box_beforenm";
     hex_of_str (write_key pk); hex_of_str (write_key sk')]

let pynacl_box_afternm ((pk,sk),(pk',sk'),message,nonce) =
  let k = box_beforenm sk' pk in
  assert_command
    ~foutput:(check_nacl (write_ciphertext (box_afternm k message ~nonce)))
    pynacl_test
    ["-f"; "box_afternm";
     hex_of_str message; hex_of_str (write_nonce nonce);
     hex_of_str (write_key k)]

let pynacl_box_open_afternm ((pk,sk),(pk',sk'),message,nonce) =
  let k = box_beforenm sk' pk in
  let c = box_afternm k message ~nonce in
  assert_command
    ~foutput:(check_nacl (box_open_afternm k c ~nonce))
    pynacl_test
    ["-f"; "box_open_afternm";
     hex_of_str (write_ciphertext c); hex_of_str (write_nonce nonce);
     hex_of_str (write_key k)]

let pynacl = "pynacl" >::: [
  "test_box"
  >:: (bracket setup pynacl_box teardown);
  "test_box_open"
  >:: (bracket setup pynacl_box_open teardown);
  "test_box_beforenm"
  >:: (bracket setup pynacl_box_beforenm teardown);
  "test_box_afternm"
  >:: (bracket setup pynacl_box_afternm teardown);
  "test_box_open_afternm"
  >:: (bracket setup pynacl_box_open_afternm teardown);
]

let suite = "Test crypto_box" >::: [ invariants; convenience; pynacl; ]

;;

run_test_tt_main suite
