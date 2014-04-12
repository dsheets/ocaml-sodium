(*
 * Copyright (c) 2013 David Sheets <sheets@alum.mit.edu>
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

module type IO = sig
  include Sodium.Box.S

  val ts : string -> storage
  val st : storage -> string
end

module Test(In : IO)(Out : IO) = struct
  module Box = Sodium.Box

  let oi x = Out.ts (In.st x)

  let setup () =
    (Box.random_keypair (), Box.random_keypair (),
     "The rooster crows at midnight.", Box.random_nonce ())

  let drop_byte s = String.sub s 0 ((String.length s)-1)
  let add_byte  s = s^"\000"
  let inv_byte  s =
    let s = String.copy s in
    s.[0] <- (char_of_int (0xff lxor (int_of_char s.[0])));
    s

  let test_right_inverse ctxt =
    let ((sk,pk),(sk',pk'),message,nonce) = setup () in
    assert_equal message
      (Out.st (Out.box_open sk' pk (oi (In.box sk pk' (In.ts message) nonce)) nonce))

  let test_right_inverse_fail_sk ctxt =
    let ((sk,pk),(sk',pk'),message,nonce) = setup () in
    let perturb_sk sk fn =
      Box.String.to_secret_key (fn (Box.String.of_secret_key sk)) in
    assert_raises (Sodium.Size_mismatch "Box.to_secret_key") (fun () ->
      Out.box_open (perturb_sk sk' drop_byte) pk
        (oi (In.box sk pk' (In.ts message) nonce)) nonce);
    assert_raises (Sodium.Size_mismatch "Box.to_secret_key") (fun () ->
      Out.box_open (perturb_sk sk' add_byte) pk
        (oi (In.box sk pk' (In.ts message) nonce)) nonce);
    assert_raises Sodium.Verification_failure (fun () ->
      Out.box_open (perturb_sk sk' inv_byte) pk
        (oi (In.box sk pk' (In.ts message) nonce)) nonce);
    ()

  let test_right_inverse_fail_pk ctxt =
    let ((sk,pk),(sk',pk'),message,nonce) = setup () in
    let perturb_pk pk fn =
      Box.String.to_public_key (fn (Box.String.of_public_key pk)) in
    assert_raises (Sodium.Size_mismatch "Box.to_public_key") (fun () ->
      Out.box_open sk' pk (oi (In.box sk (perturb_pk pk' drop_byte)
                                       (In.ts message) nonce)) nonce);
    assert_raises (Sodium.Size_mismatch "Box.to_public_key") (fun () ->
      Out.box_open sk' pk (oi (In.box sk (perturb_pk pk' add_byte)
                                       (In.ts message) nonce)) nonce);
    assert_raises Sodium.Verification_failure (fun () ->
      Out.box_open sk' pk (oi (In.box sk (perturb_pk pk' inv_byte)
                                       (In.ts message) nonce)) nonce);
    ()

  let test_right_inverse_fail_ciphertext ctxt =
    let ((sk,pk),(sk',pk'),message,nonce) = setup () in
    let perturb_ciphertext ct fn =
      Out.ts (fn (In.st ct)) in
    assert_raises Sodium.Verification_failure (fun () ->
      Out.box_open sk' pk
        (perturb_ciphertext (In.box sk pk' (In.ts message) nonce) drop_byte) nonce);
    assert_raises Sodium.Verification_failure (fun () ->
      Out.box_open sk' pk
        (perturb_ciphertext (In.box sk pk' (In.ts message) nonce) add_byte) nonce);
    assert_raises Sodium.Verification_failure (fun () ->
      Out.box_open sk' pk
        (perturb_ciphertext (In.box sk pk' (In.ts message) nonce) inv_byte) nonce);
    ()

  let test_right_inverse_fail_nonce ctxt =
    let ((sk,pk),(sk',pk'),message,nonce) = setup () in
    let perturb_nonce n fn =
      Box.String.to_nonce (fn (Box.String.of_nonce n)) in
    assert_raises (Sodium.Size_mismatch "Box.to_nonce") (fun () ->
      Out.box_open sk' pk (oi (In.box sk pk' (In.ts message) nonce))
        (perturb_nonce nonce drop_byte));
    assert_raises (Sodium.Size_mismatch "Box.to_nonce") (fun () ->
      Out.box_open sk' pk (oi (In.box sk pk' (In.ts message) nonce))
        (perturb_nonce nonce add_byte));
    assert_raises Sodium.Verification_failure (fun () ->
      Out.box_open sk' pk (oi (In.box sk pk' (In.ts message) nonce))
        (perturb_nonce nonce inv_byte));
    ()

  let test_channel_key_eq ctxt =
    let ((sk,pk),(sk',pk'),message,nonce) = setup () in
    assert_equal (Box.precompute sk pk')
                 (Box.precompute sk' pk)

  let test_right_inverse_channel_key ctxt =
    let ((sk,pk),(sk',pk'),message,nonce) = setup () in
    let ck = Box.precompute sk pk' in
    let ck'= Box.precompute sk' pk in
    assert_equal message
                 (Out.st (Out.fast_box_open ck'
                    (oi (In.fast_box ck (In.ts message) nonce)) nonce))

  let test_right_inverse_channel_key_fail ctxt =
    let ((sk,pk),(sk',pk'),message,nonce) = setup () in
    let ck = Box.precompute sk pk' in
    let ck'= Box.precompute sk' pk in
    let perturb_ciphertext ct fn =
      Out.ts (fn (In.st ct)) in
    assert_raises Sodium.Verification_failure (fun () ->
      Out.fast_box_open ck'
        (perturb_ciphertext (In.fast_box ck (In.ts message) nonce) drop_byte) nonce);
    assert_raises Sodium.Verification_failure (fun () ->
      Out.fast_box_open ck'
        (perturb_ciphertext (In.fast_box ck (In.ts message) nonce) add_byte) nonce);
    assert_raises Sodium.Verification_failure (fun () ->
      Out.fast_box_open ck'
        (perturb_ciphertext (In.fast_box ck (In.ts message) nonce) inv_byte) nonce);
    ()

  let invariants = "invariants" >::: [
      "test_right_inverse" >:: test_right_inverse;
      "test_right_inverse_fail_sk" >:: test_right_inverse_fail_sk;
      "test_right_inverse_fail_pk" >:: test_right_inverse_fail_pk;
      "test_right_inverse_fail_ciphertext" >:: test_right_inverse_fail_ciphertext;
      "test_right_inverse_fail_nonce" >:: test_right_inverse_fail_nonce;
      "test_channel_key_eq" >:: test_channel_key_eq;
      "test_right_inverse_channel_key" >:: test_right_inverse_channel_key;
      "test_right_inverse_channel_key_fail" >:: test_right_inverse_channel_key_fail;
    ]

  let test_effective_wipe ctxt =
    let ((sk,pk),(sk',pk'),message,nonce) = setup () in
    let ck  = Box.precompute sk pk' in
    let cct = oi (In.fast_box ck (In.ts message) nonce) in
    let ct  = oi (In.box sk pk' (In.ts message) nonce) in
    assert_equal message (Out.st (Out.box_open sk' pk ct nonce));
    assert_equal message (Out.st (Out.fast_box_open ck cct nonce));
    Box.wipe_key sk';
    assert_raises Sodium.Verification_failure (fun () ->
      assert_equal message (Out.st (Out.box_open sk' pk ct nonce)));
    Box.wipe_key ck;
    assert_raises Sodium.Verification_failure (fun () ->
      assert_equal message (Out.st (Out.fast_box_open ck cct nonce)));
    ()

  let test_equal_public_keys ctxt =
    let pk   = String.make (Box.public_key_size) 'A' in
    let pk'  = "B" ^ (String.make (Box.public_key_size - 1) 'A') in
    let pk'' = (String.make (Box.public_key_size - 1) 'A') ^ "B" in
    assert_bool "=" (Box.equal_public_keys (Box.String.to_public_key pk)
                                (Box.String.to_public_key pk));
    assert_bool "<>" (not (Box.equal_public_keys (Box.String.to_public_key pk)
                                      (Box.String.to_public_key pk')));
    assert_bool "<>" (not (Box.equal_public_keys (Box.String.to_public_key pk)
                                      (Box.String.to_public_key pk'')));
    ()

  let test_equal_secret_keys ctxt =
    let sk   = String.make (Box.secret_key_size) 'A' in
    let sk'  = "B" ^ (String.make (Box.secret_key_size - 1) 'A') in
    let sk'' = (String.make (Box.secret_key_size - 1) 'A') ^ "B" in
    assert_bool "=" (Box.equal_secret_keys (Box.String.to_secret_key sk)
                                (Box.String.to_secret_key sk));
    assert_bool "<>" (not (Box.equal_secret_keys (Box.String.to_secret_key sk)
                                      (Box.String.to_secret_key sk')));
    assert_bool "<>" (not (Box.equal_secret_keys (Box.String.to_secret_key sk)
                                      (Box.String.to_secret_key sk'')));
    ()

  let test_equal_channel_keys ctxt =
    let ck   = String.make (Box.channel_key_size) 'A' in
    let ck'  = "B" ^ (String.make (Box.channel_key_size - 1) 'A') in
    let ck'' = (String.make (Box.channel_key_size - 1) 'A') ^ "B" in
    assert_bool "=" (Box.equal_channel_keys (Box.String.to_channel_key ck)
                                (Box.String.to_channel_key ck));
    assert_bool "<>" (not (Box.equal_channel_keys (Box.String.to_channel_key ck)
                                      (Box.String.to_channel_key ck')));
    assert_bool "<>" (not (Box.equal_channel_keys (Box.String.to_channel_key ck)
                                      (Box.String.to_channel_key ck'')));
    ()

  let test_compare_public_keys ctxt =
    let pk   = String.make (Box.public_key_size) 'A' in
    let pk'  = (String.make (Box.public_key_size - 1) 'A') ^ "0" in
    let pk'' = "B" ^ (String.make (Box.public_key_size - 1) 'A') in
    assert_equal 0    (Box.compare_public_keys (Box.String.to_public_key pk)
                                      (Box.String.to_public_key pk));
    assert_equal 1    (Box.compare_public_keys (Box.String.to_public_key pk)
                                      (Box.String.to_public_key pk'));
    assert_equal (-1) (Box.compare_public_keys (Box.String.to_public_key pk)
                                      (Box.String.to_public_key pk''));
    ()

  let test_nonce_operations ctxt =
    let n     = String.make Box.nonce_size '\x00' in
    let n'    = (String.make (Box.nonce_size - 1) '\x00') ^ "\x01" in
    let n''   = (String.make (Box.nonce_size - 1) '\x00') ^ "\x02" in
    let n'''  = (String.make (Box.nonce_size - 3) '\x00') ^ "\x02\x00\x00" in
    let n'''' = String.make Box.nonce_size '\xff' in
    assert_bool "=" ((Box.nonce_of_string n) = (Box.nonce_of_string n));
    assert_bool "<>" ((Box.nonce_of_string n) <> (Box.nonce_of_string n'));
    assert_raises (Sodium.Size_mismatch "Box.nonce_of_string")
                  (fun () -> Box.nonce_of_string (n ^ "."));
    assert_equal (Box.nonce_of_string n')
                 (Box.increment_nonce (Box.nonce_of_string n));
    assert_equal (Box.nonce_of_string n'')
                 (Box.increment_nonce ~step:2 (Box.nonce_of_string n));
    assert_equal (Box.nonce_of_string n''')
                 (Box.increment_nonce ~step:0x20000 (Box.nonce_of_string n));
    assert_equal (Box.nonce_of_string n'''')
                 (Box.increment_nonce ~step:(-1) (Box.nonce_of_string n))

  let convenience = "convenience" >::: [
    "test_wipe"                >:: test_effective_wipe;
    "test_equal_public_keys"   >:: test_equal_public_keys;
    "test_equal_secret_keys"   >:: test_equal_secret_keys;
    "test_equal_channel_keys"  >:: test_equal_channel_keys;
    "test_compare_public_keys" >:: test_compare_public_keys;
    "test_nonce_operations"    >:: test_nonce_operations;
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

  let nacl_runner = "_build/lib_test/nacl_runner"
  let test_nacl_box ctxt =
    let ((sk,pk),(sk',pk'),message,nonce) = setup () in
    let cs = In.st (In.box sk' pk (In.ts message) nonce) in
    let args = [
      "box";
      hex_of_str message;
      hex_of_str (Box.String.of_nonce nonce);
      hex_of_str (Box.String.of_public_key pk);
      hex_of_str (Box.String.of_secret_key sk');
    ] in
    assert_command ~ctxt
      ~foutput:(check_nacl cs) nacl_runner args

  let test_nacl_box_open ctxt =
    let ((sk,pk),(sk',pk'),message,nonce) = setup () in
    let c = In.box sk' pk (In.ts message) nonce in
    assert_command ~ctxt
      ~foutput:(check_nacl (Out.st (Out.box_open sk pk' (oi c) nonce)))
      nacl_runner
      ["box_open";
       hex_of_str (In.st c);
       hex_of_str (Box.String.of_nonce nonce);
       hex_of_str (Box.String.of_public_key pk');
       hex_of_str (Box.String.of_secret_key sk)]

  let test_nacl_box_beforenm ctxt =
    let ((sk,pk),(sk',pk'),message,nonce) = setup () in
    assert_command ~ctxt
      ~foutput:(check_nacl (Box.String.of_channel_key (Box.precompute sk' pk)))
      nacl_runner
      ["box_beforenm";
       hex_of_str (Box.String.of_public_key pk);
       hex_of_str (Box.String.of_secret_key sk')]

  let test_nacl_box_afternm ctxt =
    let ((sk,pk),(sk',pk'),message,nonce) = setup () in
    let ck = Box.precompute sk' pk in
    assert_command ~ctxt
      ~foutput:(check_nacl (Out.st (Out.fast_box ck (Out.ts message) nonce)))
      nacl_runner
      ["box_afternm";
       hex_of_str message;
       hex_of_str (Box.String.of_nonce nonce);
       hex_of_str (Box.String.of_channel_key ck)]

  let test_nacl_box_open_afternm ctxt =
    let ((sk,pk),(sk',pk'),message,nonce) = setup () in
    let ck = Box.precompute sk' pk in
    let c = In.fast_box ck (In.ts message) nonce in
    assert_command ~ctxt
      ~foutput:(check_nacl (Out.st (Out.fast_box_open ck (oi c) nonce)))
      nacl_runner
      ["box_open_afternm";
       hex_of_str (In.st c);
       hex_of_str (Box.String.of_nonce nonce);
       hex_of_str (Box.String.of_channel_key ck)]

  let nacl = "nacl" >::: [
      "test_box" >:: test_nacl_box;
      "test_box_open" >:: test_nacl_box_open;
      "test_box_beforenm" >:: test_nacl_box_beforenm;
      "test_box_afternm" >:: test_nacl_box_afternm;
      "test_box_open_afternm" >:: test_nacl_box_open_afternm;
    ]

  let suite = [
      invariants;
      convenience;
      nacl;
    ]
end

module IO_bigstring = struct
  include Sodium.Box.Bigstring

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

module IO_string = struct
  include Sodium.Box.String

  let ts s = s
  let st t = t
end

let suite = "Box" >::: [
    "String -> String"       >::: (let module M = Test(IO_string)(IO_string) in M.suite);
    "Bigstring -> String"    >::: (let module M = Test(IO_bigstring)(IO_string) in M.suite);
    "String -> Bigstring"    >::: (let module M = Test(IO_string)(IO_bigstring) in M.suite);
    "Bigstring -> Bigstring" >::: (let module M = Test(IO_bigstring)(IO_bigstring) in M.suite);
  ]
