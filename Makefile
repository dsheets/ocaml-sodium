include $(shell ocamlc -where)/Makefile.config

OCAMLBUILD = ocamlbuild -use-ocamlfind -classic-display

all:
	$(OCAMLBUILD) lib/sodium.cma lib/sodium.cmxa

clean:
	$(OCAMLBUILD) -clean

test: _build/lib_test/nacl_runner
	CAML_LD_LIBRARY_PATH=_build/lib:$(CAML_LD_LIBRARY_PATH) \
		$(OCAMLBUILD) lib_test/test_sodium.byte --
	$(OCAMLBUILD) lib_test/test_sodium.native --

install: all
	ocamlfind install sodium lib/META \
		$(addprefix _build/lib/,sodium.mli sodium.cmi sodium.cmt sodium.cma sodium.cmxa \
		                        sodium$(EXT_LIB) dllsodium_stubs$(EXT_DLL) libsodium_stubs$(EXT_LIB))

uninstall:
	ocamlfind remove sodium

reinstall: uninstall install

.PHONY: all clean test install uninstall reinstall

_build/%: %.c
	mkdir -p $$(dirname $@)
	$(CC) -Wall -g -lsodium -o $@ $^
