open Ocamlbuild_plugin;;

dispatch begin
  function
  | After_rules ->
    (* flag ["compile"; "ocaml"] (A"-safe-string"); *)

    flag ["link"; "library"; "ocaml"; "byte"; "use_sodium"]
      (S[A"-dllib"; A("-lsodium"); A"-cclib"; A("-lsodium")]);

    flag ["link"; "library"; "ocaml"; "native"; "use_sodium"]
      (S[A"-cclib"; A("-lsodium")]);

    flag ["link"; "program"; "ocaml"; "byte"; "use_sodium"]
      (S[A"-dllib"; A("dllsodium")]);

    flag ["link"; "program"; "ocaml"; "native"; "use_sodium"]
      (S[A"-cclib"; A("-lsodium")]);

  | _ -> ()
end;;
