open Ocamlbuild_plugin;;
open Ocamlbuild_pack;;

let libdir = Sys.getenv "OCAML_LIB_DIR" in

dispatch begin
  function
  | After_rules ->

    rule "cstubs: lib/x_bindings.ml -> x_stubs.c, x_stubs.ml"
      ~prods:["lib/%_stubs.c"; "lib/%_generated.ml"]
      ~deps: ["lib_gen/%_bindgen.byte"]
      (fun env build ->
        Cmd (A(env "lib_gen/%_bindgen.byte")));

    copy_rule "cstubs: lib_gen/x_bindings.ml -> lib/x_bindings.ml"
      "lib_gen/%_bindings.ml" "lib/%_bindings.ml";

    flag ["c"; "compile"] & S[A"-ccopt"; A"-I/usr/local/include"];
    flag ["c"; "ocamlmklib"] & A"-L/usr/local/lib";
    flag ["ocaml"; "link"; "native"; "program"] &
      S[A"-cclib"; A"-L/usr/local/lib"];

    (* Linking cstubs *)
    flag ["c"; "compile"; "use_ctypes"] & S[A"-I"; A libdir];
    flag ["c"; "compile"; "debug"] & A"-g";

    (* Linking sodium *)
    flag ["c"; "compile"; "use_sodium"] &
      S[A"-ccopt"; A"--std=c99 -Wall -pedantic -Werror -Wno-pointer-sign"];
    flag ["c"; "ocamlmklib"; "use_sodium"] & A"-lsodium";

    (* Linking generated stubs *)
    dep ["ocaml"; "link"; "byte"; "library"; "use_sodium_stubs"]
      ["lib/dllsodium_stubs"-.-(!Options.ext_dll)];
    flag ["ocaml"; "link"; "byte"; "library"; "use_sodium_stubs"] &
      S[A"-dllib"; A"-lsodium_stubs"];

    dep ["ocaml"; "link"; "native"; "library"; "use_sodium_stubs"]
      ["lib/libsodium_stubs"-.-(!Options.ext_lib)];
    flag ["ocaml"; "link"; "native"; "library"; "use_sodium_stubs"] &
      S[A"-cclib"; A"-lsodium_stubs"; A"-cclib"; A"-lsodium"];

    (* Linking tests *)
    flag ["ocaml"; "link"; "byte"; "program"; "use_sodium_stubs"] &
      S[A"-dllib"; A"-lsodium_stubs"];
    dep ["ocaml"; "link"; "native"; "program"; "use_sodium_stubs"]
      ["lib/libsodium_stubs"-.-(!Options.ext_lib)];
    flag ["ocaml"; "link"; "native"; "program"; "use_sodium_stubs"] &
      S[A"-cclib"; A"-lsodium"];

  | _ -> ()
end;;
