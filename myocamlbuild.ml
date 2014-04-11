open Ocamlbuild_plugin;;

dispatch begin
  function
  | After_rules ->
    flag ["ocaml"; "compile"] (S[A"-w"; A"@5@8@10@11@12@14@23@24@26@29"]);

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
