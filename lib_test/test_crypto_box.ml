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

module type IO = sig
  include Sodium.Serialize.S

  val ts : string -> t
  val st : t -> string
end

module Test(I : IO)(O : IO) = struct
  module Box = Sodium.Box
  module In = Box.Make(I)
  module Out = Box.Make(O)

  let setup _ =
    let nonce = In.box_read_nonce (I.ts "012345678901234567890123") in
    (In.box_keypair (),Out.box_keypair (),
     "The rooster crows at midnight.",nonce)

  let teardown _ = ()

  let drop_byte s = String.sub s 0 ((String.length s)-1)
  let add_byte s = s^"\000"
  let inv_byte s = s.[0] <- (char_of_int (0xff lxor (int_of_char s.[0]))); s

  let right_inverse ((pk,sk),(pk',sk'),message,nonce) =
    assert_equal message
      (O.st (Out.box_open sk' pk (In.box sk pk' (I.ts message) ~nonce) ~nonce))

  let right_inverse_fail_sk ((pk,sk),(pk',sk'),message,nonce) =
    let perturb_sk sk fn =
      Out.box_read_secret_key (O.ts (fn (O.st (Out.box_write_key sk)))) in
    assert_raises Sodium.KeyError (fun () ->
      Out.box_open (perturb_sk sk' drop_byte) pk
        (In.box sk pk' (I.ts message) ~nonce) ~nonce);
    assert_raises Sodium.KeyError (fun () ->
      Out.box_open (perturb_sk sk' add_byte) pk
        (In.box sk pk' (I.ts message) ~nonce) ~nonce);
    assert_raises Sodium.VerificationFailure (fun () ->
      Out.box_open (perturb_sk sk' inv_byte) pk
        (In.box sk pk' (I.ts message) ~nonce) ~nonce);
    ()

  let right_inverse_fail_pk ((pk,sk),(pk',sk'),message,nonce) =
    let perturb_pk pk fn =
      Out.box_read_public_key (O.ts (fn (O.st (Out.box_write_key sk)))) in
    assert_raises Sodium.KeyError (fun () ->
      Out.box_open sk' pk (In.box sk (perturb_pk pk' drop_byte)
                             (I.ts message) ~nonce) ~nonce);
    assert_raises Sodium.KeyError (fun () ->
      Out.box_open sk' pk (In.box sk (perturb_pk pk' add_byte)
                             (I.ts message) ~nonce) ~nonce);
    assert_raises Sodium.VerificationFailure (fun () ->
      Out.box_open sk' pk (In.box sk (perturb_pk pk' inv_byte)
                             (I.ts message) ~nonce) ~nonce);
    ()

  let right_inverse_fail_ciphertext ((pk,sk),(pk',sk'),message,nonce) =
    let perturb_ciphertext ct fn =
      Out.box_read_ciphertext (O.ts (fn (I.st (In.box_write_ciphertext ct)))) in
    assert_raises Sodium.VerificationFailure (fun () ->
      Out.box_open sk' pk
        (perturb_ciphertext (In.box sk pk' (I.ts message) ~nonce) drop_byte)
        ~nonce);
    assert_raises Sodium.VerificationFailure (fun () ->
      Out.box_open sk' pk
        (perturb_ciphertext (In.box sk pk' (I.ts message) ~nonce) add_byte)
        ~nonce);
    assert_raises Sodium.VerificationFailure (fun () ->
      Out.box_open sk' pk
        (perturb_ciphertext (In.box sk pk' (I.ts message) ~nonce) inv_byte)
        ~nonce);
    ()

  let right_inverse_fail_nonce ((pk,sk),(pk',sk'),message,nonce) =
    let perturb_nonce n fn =
      In.box_read_nonce (I.ts (fn (I.st (In.box_write_nonce n)))) in
    assert_raises Sodium.NonceError (fun () ->
      Out.box_open sk' pk
        (In.box sk pk' (I.ts message) ~nonce)
        ~nonce:(perturb_nonce nonce drop_byte));
    assert_raises Sodium.NonceError (fun () ->
      Out.box_open sk' pk
        (In.box sk pk' (I.ts message) ~nonce)
        ~nonce:(perturb_nonce nonce add_byte));
    assert_raises Sodium.VerificationFailure (fun () ->
      Out.box_open sk' pk
        (In.box sk pk' (I.ts message) ~nonce)
        ~nonce:(perturb_nonce nonce inv_byte));
    ()

  let channel_key_eq ((pk,sk),(pk',sk'),message,nonce) =
    assert_equal
      (O.st (Out.box_write_key (Out.box_beforenm sk pk')))
      (I.st (In.box_write_key (In.box_beforenm sk' pk)))

  let right_inverse_channel_key ((pk,sk),(pk',sk'),message,nonce) =
    let ck = In.box_beforenm sk pk' in
    let ck'= Out.box_beforenm sk' pk in
    assert_equal
      message
      (O.st (Out.box_open_afternm ck'
               (In.box_afternm ck (I.ts message) ~nonce) ~nonce))

  let right_inverse_channel_key_fail ((pk,sk),(pk',sk'),message,nonce) =
    let ck = In.box_beforenm sk pk' in
    let ck'= Out.box_beforenm sk' pk in
    let perturb_ciphertext ct fn =
      Out.box_read_ciphertext (O.ts (fn (I.st (In.box_write_ciphertext ct)))) in
    assert_raises Sodium.VerificationFailure (fun () ->
      Out.box_open_afternm ck'
        (perturb_ciphertext (In.box_afternm ck (I.ts message) ~nonce) drop_byte)
        ~nonce);
    assert_raises Sodium.VerificationFailure (fun () ->
      Out.box_open_afternm ck'
        (perturb_ciphertext (In.box_afternm ck (I.ts message) ~nonce) add_byte)
        ~nonce);
    assert_raises Sodium.VerificationFailure (fun () ->
      Out.box_open_afternm ck'
        (perturb_ciphertext (In.box_afternm ck (I.ts message) ~nonce) inv_byte)
        ~nonce);
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
    let ck = In.box_beforenm sk pk' in
    let cct = In.box_afternm ck (I.ts message) ~nonce in
    let ct = In.box sk pk' (I.ts message) ~nonce in
    assert_equal message (O.st (Out.box_open sk' pk ct ~nonce));
    assert_equal message (O.st (Out.box_open_afternm ck cct ~nonce));
    Box.wipe_key sk';
    assert_raises Sodium.VerificationFailure (fun () ->
      assert (message = (O.st (Out.box_open sk' pk ct ~nonce)))
    );
    Box.wipe_key ck;
    assert_raises Sodium.VerificationFailure (fun () ->
      assert (message = (O.st (Out.box_open_afternm ck cct ~nonce)))
    );
    ()

  let compare_keys_eq ((pk,sk),(pk',sk'),message,nonce) =
    let neq_msg = "different keys shouldn't be equal" in
    assert_equal 0 (Box.compare_keys pk pk);
    assert_equal 0 (Box.compare_keys pk' pk');
    assert_bool neq_msg (0 <> (Box.compare_keys pk pk'));
    ()

  let compare_keys_trans ((pk,sk),(pk',sk'),message,nonce) =
    let (pk'',sk'') = Out.box_keypair () in
    let pks = List.sort Box.compare_keys [pk;pk';pk''] in
    let check_trans = function
      | [a;b;c] ->
          assert_equal 1 (Box.compare_keys c b);
          assert_equal 1 (Box.compare_keys b a);
          assert_equal 1 (Box.compare_keys c a);
      | _ -> assert_failure "broken test"
    in
    check_trans pks;
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

  let nacl_test = "_build/lib_test/nacl_test"
  let nacl_box ((pk,sk),(pk',sk'),message,nonce) =
    let cs = O.st (Out.box_write_ciphertext
                     (In.box sk' pk (I.ts message) ~nonce)) in
    let args = [
      "box";
      hex_of_str message; hex_of_str (I.st (In.box_write_nonce nonce));
      hex_of_str (I.st (In.box_write_key pk));
      hex_of_str (O.st (Out.box_write_key sk'));
    ] in
    assert_command ~foutput:(check_nacl cs) nacl_test args

  let nacl_box_open ((pk,sk),(pk',sk'),message,nonce) =
    let c = In.box sk' pk (I.ts message) ~nonce in
    assert_command
      ~foutput:(check_nacl (O.st (Out.box_open sk pk' c ~nonce)))
      nacl_test
      ["box_open";
       hex_of_str (O.st (Out.box_write_ciphertext c));
       hex_of_str (O.st (Out.box_write_nonce nonce));
       hex_of_str (I.st (In.box_write_key pk'));
       hex_of_str (I.st (In.box_write_key sk))]

  let nacl_box_beforenm ((pk,sk),(pk',sk'),message,nonce) =
    assert_command
      ~foutput:(check_nacl (O.st (Out.box_write_key (In.box_beforenm sk' pk))))
      nacl_test
      ["box_beforenm";
       hex_of_str (O.st (Out.box_write_key pk));
       hex_of_str (O.st (Out.box_write_key sk'))]

  let nacl_box_afternm ((pk,sk),(pk',sk'),message,nonce) =
    let k = Out.box_beforenm sk' pk in
    assert_command
      ~foutput:(check_nacl (I.st (In.box_write_ciphertext
                                    (Out.box_afternm k (O.ts message) ~nonce))))
      nacl_test
      ["box_afternm";
       hex_of_str message; hex_of_str (I.st (In.box_write_nonce nonce));
       hex_of_str (O.st (Out.box_write_key k))]

  let nacl_box_open_afternm ((pk,sk),(pk',sk'),message,nonce) =
    let k = In.box_beforenm sk' pk in
    let c = In.box_afternm k (I.ts message) ~nonce in
    assert_command
      ~foutput:(check_nacl (O.st (Out.box_open_afternm k c ~nonce)))
      nacl_test
      ["box_open_afternm";
       hex_of_str (O.st (Out.box_write_ciphertext c));
       hex_of_str (I.st (In.box_write_nonce nonce));
       hex_of_str (I.st (In.box_write_key k))]

  let nacl = "nacl" >::: [
    "test_box"
    >:: (bracket setup nacl_box teardown);
    "test_box_open"
    >:: (bracket setup nacl_box_open teardown);
    "test_box_beforenm"
    >:: (bracket setup nacl_box_beforenm teardown);
    "test_box_afternm"
    >:: (bracket setup nacl_box_afternm teardown);
    "test_box_open_afternm"
    >:: (bracket setup nacl_box_open_afternm teardown);
  ]

  let suite = "Test crypto_box" >::: [ invariants; convenience; nacl; ]
end

module Bigarray = struct
  include Sodium.Serialize.Bigarray

  let ts s =
    let len = String.length s in
    let b = Bigarray.(Array1.create char c_layout len) in
    for i = 0 to len - 1 do b.{i} <- s.[i] done;
    b
  let st t =
    let len = Bigarray.Array1.dim t in
    let s = String.create len in
    for i = 0 to len - 1 do s.[i] <- t.{i} done;
    s
end

module String = struct
  include Sodium.Serialize.String

  let ts s = s
  let st t = t
end

module StringString = Test(String)(String)
module BigarrayString = Test(Bigarray)(String)
module StringBigarray = Test(String)(Bigarray)
module BigarrayBigarray = Test(Bigarray)(Bigarray)

let suite = "Test" >::: [
  "String -> String" >:::
    StringString.([invariants; convenience; nacl]);
  "Bigarray -> String" >:::
    BigarrayString.([invariants; convenience; nacl]);
  "String -> Bigarray" >:::
    StringBigarray.([invariants; convenience; nacl]);
  "Bigarray -> Bigarray" >:::
    BigarrayBigarray.([invariants; convenience; nacl]);
]

let _ =
  run_test_tt_main suite
