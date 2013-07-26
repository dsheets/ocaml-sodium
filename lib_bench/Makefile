.PHONY: all

all:
	ocamlbuild -clean
	ocamlbuild -use-ocamlfind -tag thread -pkgs core,sodium,core_bench \
		benchmark.native
	./benchmark.native -clear-columns +name cycles -save -display blank
