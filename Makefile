all: _build/lib/dllsodium.so
	ocamlbuild -use-ocamlfind lib/sodium.cma lib/sodium.cmxa

clean:
	ocamlbuild -use-ocamlfind -clean

test: _build/lib_test/nacl_runner
	ocamlbuild -use-ocamlfind lib_test/test_sodium.native --

install: all
	ocamlfind install sodium lib/META \
		$(addprefix _build/,lib/*.mli lib/*.cmi lib/*.cmt lib/*.cma lib/*.cmxa
		                    lib/*.a lib/*.so)

uninstall:
	ocamlfind remove sodium

reinstall: uninstall install

.PHONY: all clean test install uninstall reinstall

_build/lib/dllsodium.so:
	mkdir -p $$(dirname $@)
	$(CC) -shared -lsodium -o $@

_build/%: %.c
	mkdir -p $$(dirname $@)
	$(CC) -Wall -g -lsodium -o $@ $^
