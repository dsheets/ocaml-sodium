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

module Test(A: sig
    include module type of Hash.Sha256
    val name : string
    val expected_primitive : string
    val vector : string
  end) = struct
  let test_digest ctxt =
    A.(assert_equal expected_primitive primitive);
    let hash  = A.Bytes.digest (Bytes.of_string "The quick brown fox jumps over the lazy dog") in
    assert_equal (Bytes.of_string A.vector) (A.Bytes.of_hash hash)

  let test_serialize ctxt =
    let hash = A.Bytes.digest (Bytes.of_string "The quick brown fox jumps over the lazy dog") in
    assert_equal (A.Bytes.to_hash (A.Bytes.of_hash hash)) hash;
    assert_equal (A.Bigbytes.to_hash (A.Bigbytes.of_hash hash)) hash

  let test_equal ctxt =
    let h   = Bytes.of_string (String.make (A.size) 'A') in
    let h'  = Bytes.of_string ("B" ^ (String.make (A.size - 1) 'A')) in
    let h'' = Bytes.of_string ((String.make (A.size - 1) 'A') ^ "B") in
    assert_bool "=" (A.equal (A.Bytes.to_hash h)
                       (A.Bytes.to_hash h));
    assert_bool "<>" (not (A.equal (A.Bytes.to_hash h)
                             (A.Bytes.to_hash h')));
    assert_bool "<>" (not (A.equal (A.Bytes.to_hash h)
                             (A.Bytes.to_hash h'')))

  let test_permute ctxt =
    let hash  = A.Bytes.digest (Bytes.of_string "The quick brown fox jumps over the lazy dog") in
    assert_raises (Size_mismatch (A.name^".to_hash"))
      (fun () -> (A.Bytes.to_hash (add_byte (A.Bytes.of_hash hash))))

  let suite = A.name >::: [
      "test_digest"    >:: test_digest;
      "test_serialize" >:: test_serialize;
      "test_equal"     >:: test_equal;
      "test_permute"   >:: test_permute;
    ]
end

let vector_sha256 =
  "\xd7\xa8\xfb\xb3\x07\xd7\x80\x94\x69\xca\x9a\xbc\xb0\x08\x2e\x4f\x8d\
   \x56\x51\xe4\x6d\x3c\xdb\x76\x2d\x02\xd0\xbf\x37\xc9\xe5\x92"

let vector_sha512 =
  "\x07\xe5\x47\xd9\x58\x6f\x6a\x73\xf7\x3f\xba\xc0\x43\x5e\xd7\x69\x51\
   \x21\x8f\xb7\xd0\xc8\xd7\x88\xa3\x09\xd7\x85\x43\x6b\xbb\x64\x2e\x93\
   \xa2\x52\xa9\x54\xf2\x39\x12\x54\x7d\x1e\x8a\x3b\x5e\xd6\xe1\xbf\xd7\
   \x09\x78\x21\x23\x3f\xa0\x53\x8f\x3d\xb8\x54\xfe\xe6"

let suite = "*hash" >::: [
    (let module M = Test(struct include Hash.Sha256 let name = "Hash.Sha256" let expected_primitive = "sha256" let vector = vector_sha256 end) in M.suite);
    (let module M = Test(struct include Hash.Sha512 let name = "Hash.Sha512" let expected_primitive = "sha512" let vector = vector_sha512 end) in M.suite);
  ]
