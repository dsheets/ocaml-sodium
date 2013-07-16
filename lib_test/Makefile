.PHONY: all clean

OBJS=nacl_test

all: ${OBJS}

nacl_test: nacl_test.c
	${CC} -Wall -g -o nacl_test nacl_test.c -lnacl

clean:
	rm -f ${OBJS}
