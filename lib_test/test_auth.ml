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

module Test(A: sig include module type of Auth val name : string end) = struct
  let test_equal_keys ctxt =
    let sk   = String.make (A.key_size) 'A' in
    let sk'  = "B" ^ (String.make (A.key_size - 1) 'A') in
    let sk'' = (String.make (A.key_size - 1) 'A') ^ "B" in
    assert_bool "=" (A.equal_keys (A.String.to_key sk)
                                  (A.String.to_key sk));
    assert_bool "<>" (not (A.equal_keys (A.String.to_key sk)
                                        (A.String.to_key sk')));
    assert_bool "<>" (not (A.equal_keys (A.String.to_key sk)
                                        (A.String.to_key sk'')))

  let test_permute ctxt =
    let k = A.random_key () in
    assert_raises (Size_mismatch (A.name^".to_key"))
                  (fun () -> (A.String.to_key ((A.String.of_key k) ^ "\x00")));
    assert_raises (Size_mismatch (A.name^".to_auth"))
                  (fun () -> (A.String.to_auth "\x00"))

  let setup () =
    A.random_key (), "wild wild fox"

  let test_auth_verify ctxt =
    let k, msg = setup () in
    let auth = A.String.auth k msg in
    A.String.verify k auth msg

  let test_auth_verify_fail_permute ctxt =
    let k, msg = setup () in
    let auth = A.String.auth k msg in
    let auth = let s = A.String.of_auth auth in s.[10] <- 'a'; A.String.to_auth s in
    assert_raises Verification_failure
                  (fun () -> A.String.verify k auth msg)

  let test_auth_verify_fail_key ctxt =
    let k, msg = setup () in
    let auth = A.String.auth k msg in
    let k' = A.random_key () in
    assert_raises Verification_failure
                  (fun () -> A.String.verify k' auth msg)

  let suite = A.name >::: [
      "test_equal_keys"               >:: test_equal_keys;
      "test_permute"                  >:: test_permute;
      "test_auth_verify"              >:: test_auth_verify;
      "test_auth_verify_fail_permute" >:: test_auth_verify_fail_permute;
      "test_auth_verify_fail_key"     >:: test_auth_verify_fail_key;
    ]
end

let suite = "*auth" >::: [
    (let module M = Test(struct include Auth let name = "Auth" end) in M.suite);
    (let module M = Test(struct include One_time_auth let name = "One_time_auth" end) in M.suite);
  ]
