.PHONY: all build prep pack install uninstall clean

NAME=sodium
PKGS=ctypes.foreign
OBJS=crypto_box

OCAMLOPT=ocamlopt
OCAMLC=ocamlc

CMOS=$(addprefix lib/,$(addsuffix .cmo,${OBJS}))
CMXS=$(addprefix lib/,$(addsuffix .cmx,${OBJS}))
B=_build/lib/
INSTALL=META $(addprefix ${B},${NAME}.cma ${NAME}.cmxa ${NAME}.cmi dll${NAME}.so)

build: prep pack

all: prep pack install

prep:
	mkdir -p _build/lib

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
	cc -shared -o $@ -lsodium

META: META.in
	cp META.in META

install: ${INSTALL}
	ocamlfind install ${NAME} ${INSTALL}

uninstall:
	ocamlfind remove ${NAME}

clean:
	rm -rf _build META
