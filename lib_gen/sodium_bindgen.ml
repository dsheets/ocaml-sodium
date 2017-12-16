open Ctypes

module BindStorage(T: functor(S: Sodium_storage.S) -> sig end) = struct
  module Bytes = T(Sodium_storage.Bytes)
  module Bigbytes = T(Sodium_storage.Bigbytes)
end

module Bind(F: Cstubs.FOREIGN) = struct
  include Sodium_bindings.C(F)
  module Sodium' = BindStorage(Make)
  module Random' = BindStorage(Random.Make)
  module Box' = BindStorage(Box.Make)
  module Sign' = BindStorage(Sign.Make)
  module Password_hash' = BindStorage(Password_hash.Make)
  module Secret_box' = BindStorage(Secret_box.Make)
  module Stream' = BindStorage(Stream.Make)
  module Generichash' = BindStorage(Generichash.Make)

  module Sha256 = Hash(struct
      let primitive = "sha256"
    end)
  module Sha256' = BindStorage(Sha256.Make)

  module Sha512 = Hash(struct
      let primitive = "sha512"
    end)
  module Sha512' = BindStorage(Sha512.Make)

  module Hmac_sha256 = Gen_auth(struct
    let scope     = "auth"
    let primitive = "hmacsha256"
  end)
  module Hmac_sha256' = BindStorage(Hmac_sha256.Make)

  module Hmac_sha512 = Gen_auth(struct
    let scope     = "auth"
    let primitive = "hmacsha512"
  end)
  module Hmac_sha512' = BindStorage(Hmac_sha512.Make)

  module Hmac_sha512256 = Gen_auth(struct
    let scope     = "auth"
    let primitive = "hmacsha512256"
  end)
  module Hmac_sha512256' = BindStorage(Hmac_sha512256.Make)

  module One_time_auth = Gen_auth(struct
    let scope     = "onetimeauth"
    let primitive = "poly1305"
  end)
  module One_time_auth' = BindStorage(One_time_auth.Make)
end

let () =
  let fmt = Format.formatter_of_out_channel (open_out "lib/sodium_stubs.c") in
  Format.fprintf fmt "#include <sodium.h>@.";
  Cstubs.write_c fmt ~prefix:"caml_" (module Bind);

  let fmt = Format.formatter_of_out_channel (open_out "lib/sodium_generated.ml") in
  Cstubs.write_ml fmt ~prefix:"caml_" (module Bind)
