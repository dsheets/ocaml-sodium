.PHONY: all build test prep pack install reinstall uninstall clean

NAME=sodium
PKGS=ctypes.foreign
OBJS=sodium
TESTS=test_crypto_box

CMIS=$(addprefix lib/,$(addsuffix .cmi,${OBJS}))
CMOS=$(addprefix lib/,$(addsuffix .cmo,${OBJS}))
CMXS=$(addprefix lib/,$(addsuffix .cmx,${OBJS}))
CMA=lib/${NAME}.cma
B=_build/lib/
INSTALL=META $(addprefix _build/,${CMA} ${CMXS} ${CMIS} dll${NAME}.so)

build: prep ${CMA} ${CMXS}

all: build test install

test: build $(addprefix lib_test/,$(addsuffix .native,${TESTS}))

lib_test/test_%.native: lib_test/test_%.ml
	ocamlbuild -use-ocamlfind -lflags -cclib,-lsodium -pkgs ${PKGS},oUnit \
	-I lib $@
	./test_$*.native

prep: _build/.stamp
	@ :

_build/.stamp:
	mkdir -p _build/lib
	@touch $@

%.cmo: %.ml %.mli
	ocamlbuild -use-ocamlfind -pkgs ${PKGS} $@

%.cma: ${CMOS}
	ocamlbuild -use-ocamlfind -lflags -dllib,-lsodium -pkgs ${PKGS} $@

%.cmx: %.ml %.mli
	ocamlbuild -use-ocamlfind -lflags -cclib,-lsodium -pkgs ${PKGS} $@

%.so:
	$(CC) -shared -o $@ -lsodium

META: META.in
	cp $< $@

install: build ${INSTALL}
	ocamlfind install ${NAME} ${INSTALL}

reinstall: uninstall install

uninstall:
	ocamlfind remove ${NAME}

clean:
	rm -rf _build META $(addsuffix .native,${TESTS})
