open Core.Std
open Core_bench.Std

module CryptoS = Sodium.Make(Sodium.Serialize.String)
module CryptoB = Sodium.Make(Sodium.Serialize.Bigarray)

let small  = String.create (1 lsl  7)
let medium = String.create (1 lsl 12)
let large  = String.create (1 lsl 17)

let small_s  = small
let medium_s = medium
let large_s  = large

let small_b  = Bigstring.of_string small_s
let medium_b = Bigstring.of_string medium_s
let large_b = Bigstring.of_string large_s

let nonce = CryptoS.box_read_nonce (String.create Sodium.Box.(bytes.nonce))

let print_nonce nonce = print_endline
  (String.escaped (CryptoS.box_write_nonce nonce))
let print_key key = print_endline
  (String.escaped (CryptoS.box_write_key key))

let gen_box_unbox_string m () =
  let (pk,sk) = CryptoS.box_keypair () in
  let c = CryptoS.box sk pk m ~nonce in
  let m =CryptoS.box_open sk pk c ~nonce in
  ()

let gen_box_unbox_bigarray m () =
  let (pk,sk) = CryptoB.box_keypair () in
  let c = CryptoB.box sk pk m ~nonce in
  let m = CryptoB.box_open sk pk c ~nonce in
  ()

let main () =
  let s_s = Bench.Test.create
    ~name:"gen_box_unbox_small_string"
    (gen_box_unbox_string small_s)
  in
  let m_s = Bench.Test.create
    ~name:"gen_box_unbox_medium_string"
    (gen_box_unbox_string medium_s)
  in
  let l_s = Bench.Test.create
    ~name:"gen_box_unbox_large_string"
    (gen_box_unbox_string large_s)
  in
  let s_b = Bench.Test.create
    ~name:"gen_box_unbox_small_bigarray"
    (gen_box_unbox_bigarray small_b)
  in
  let m_b = Bench.Test.create
    ~name:"gen_box_unbox_medium_bigarray"
    (gen_box_unbox_bigarray medium_b)
  in
  let l_b = Bench.Test.create
    ~name:"gen_box_unbox_large_bigarray"
    (gen_box_unbox_bigarray large_b)
  in
  Command.run (Bench.make_command [s_s; (*m_s; l_s; s_b; m_b; l_b*)])

let () = main ()
