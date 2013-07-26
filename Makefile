.PHONY: all build test prep pack install reinstall uninstall clean

NAME=sodium
VERSION=0.0.1
PKGS=ctypes.foreign,bigarray
OBJS=sodium
TESTS=test_crypto_box
TESTT=native

CMIS=$(addprefix lib/,$(addsuffix .cmi,${OBJS}))
CMOS=$(addprefix lib/,$(addsuffix .cmo,${OBJS}))
CMXS=$(addprefix lib/,$(addsuffix .cmx,${OBJS}))
CMA=lib/${NAME}.cma
CMXA=lib/${NAME}.cmxa
A=lib/${NAME}.a
B=_build/lib/
INSTALL=META $(addprefix _build/,${CMA} ${CMXA} ${A} ${CMIS} dll${NAME}.so)

FLAGS=-use-ocamlfind -tag thread

build: prep ${CMA} ${CMXA} ${A}

all: build test install

test: build $(addprefix lib_test/,$(addsuffix .${TESTT},${TESTS}))

lib_test/test_%.${TESTT}: lib_test/test_%.ml
	ocamlbuild ${FLAGS} -lflags -cclib,-lsodium -pkgs ${PKGS},oUnit \
	-I lib $@
	${MAKE} -C lib_test
	./test_$*.${TESTT}

prep: _build/.stamp
	@ :

_build/.stamp:
	mkdir -p _build/lib
	@touch $@

%.cmo: %.ml %.mli
	ocamlbuild ${FLAGS} -pkgs ${PKGS} $@

%.cma: ${CMOS}
	ocamlbuild ${FLAGS} -lflags -dllib,-lsodium,-thread -pkgs ${PKGS} $@

%.cmx: %.ml %.mli
	ocamlbuild ${FLAGS} -pkgs ${PKGS} $@

%.cmxa: ${CMXS}
	ocamlbuild ${FLAGS} -lflags -cclib,-lsodium,-thread -pkgs ${PKGS} $@

%.a: ${CMXS}
	ocamlbuild ${FLAGS} -lflags -cclib,-lsodium,-thread -pkgs ${PKGS} $@

%.so:
	$(CC) -shared -o $@ -lsodium

META: META.in
	sed s/%%VERSION%%/${VERSION}/ < META.in \
	| sed s/%%PACKAGES%%/${PKGS}/ > META

install: build ${INSTALL}
	ocamlfind install ${NAME} ${INSTALL}

reinstall: uninstall install

uninstall:
	ocamlfind remove ${NAME}

clean:
	${MAKE} -C lib_test clean
	rm -rf _build META $(addsuffix .${TESTT},${TESTS})
