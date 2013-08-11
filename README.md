# ocaml-sodium

[Ctypes](https://github.com/ocamllabs/ocaml-ctypes) bindings to
[libsodium 0.4.3+](https://github.com/jedisct1/libsodium) which wraps
[NaCl](http://nacl.cr.yp.to/). [`crypto_box`](http://nacl.cr.yp.to/box.html)
and [`crypto_sign`](http://nacl.cr.yp.to/sign.html)
functions only right now.

``` ocaml
module Crypto = Sodium.Make(Sodium.Serialize.String)
;;
let nonce = Crypto.box_read_nonce (Crypto.random Sodium.Box.(bytes.nonce)) in
let (pk, sk ) = Crypto.box_keypair () in
let (pk',sk') = Crypto.box_keypair () in
let c = Crypto.box sk pk' "Hello, Spooky World!" ~nonce in
let m = Crypto.box_open sk' pk c ~nonce in
print_endline (String.escaped (Crypto.box_write_ciphertext c));
print_endline m
```

## Considerations

Originally described in [*The Security Impact of a New Cryptographic
Library*](http://cryptojedi.org/papers/coolnacl-20111201.pdf), NaCl is a
high-level, performant cryptography library exposing a straightforward
interface.

**This binding has not been thoroughly and independently audited so your
use case must be able to tolerate this uncertainty.**

*ocaml-sodium* contains functors over serializations both for individual
 *NaCl* modules, e.g. `Sodium.Box.Make`, and as the `Sodium.Make` bundle.

Despite ocaml-sodium's thin interface on top of *libsodium*, it is still
important to be mindful of security invariants. In particular, you
should ensure that nonces used for cryptographic operations are
**never** repeated with the same key set.

## Tests

Both internal consistency tests and tests against the NaCl distribution,
rather than *libsodium*, may be found in `lib_test`.

### Salt

*Salt is very important for the camel. It needs eight times as much salt
as do cattle and sheep. A camel needs 1 kg of salt a week and it is
advisable to leave salt with camels every week.*

-- [UN FAO Manual for Primary Animal Health Care Workers](http://www.fao.org/docrep/t0690e/t0690e09.htm#unit%2061:%20feeding%20and%20watering%20of%20camels)
