.PHONY: all build prep pack install reinstall uninstall clean

NAME=sodium
PKGS=ctypes.foreign
OBJS=crypto

OCAMLOPT=ocamlopt
OCAMLC=ocamlc

CMOS=$(addprefix lib/,$(addsuffix .cmo,${OBJS}))
CMXS=$(addprefix lib/,$(addsuffix .cmx,${OBJS}))
B=_build/lib/
INSTALL=META $(addprefix ${B},${NAME}.cma ${NAME}.cmxa ${NAME}.cmi dll${NAME}.so)

build: prep pack

all: prep pack install

prep: _build/.stamp
	@ :

_build/.stamp:
	mkdir -p _build/lib
	@touch $@

pack: ${B}${NAME}.cma ${B}${NAME}.cmxa

%.cmxa: ${CMXS}
	${OCAMLOPT} -pack -o ${B}${NAME}.cmx $(addprefix _build/,${CMXS})
	${OCAMLOPT} -a -cclib -lsodium -o ${B}${NAME}.cmxa ${B}${NAME}.cmx

%.cma: ${CMOS}
	${OCAMLC} -pack -o ${B}${NAME}.cmo $(addprefix _build/,${CMOS})
	${OCAMLC} -a -dllib -lsodium -o ${B}${NAME}.cma ${B}${NAME}.cmo

%.cmo: %.ml %.mli
	ocamlbuild -use-ocamlfind -pkgs ${PKGS} $@

%.cmx: %.ml %.mli
	ocamlbuild -use-ocamlfind -pkgs ${PKGS} $@

%.so:
	$(CC) -shared -o $@ -lsodium

META: META.in
	cp $< $@

install: ${INSTALL}
	ocamlfind install ${NAME} ${INSTALL}

reinstall: uninstall install

uninstall:
	ocamlfind remove ${NAME}

clean:
	rm -rf _build META
