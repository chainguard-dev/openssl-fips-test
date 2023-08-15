PROG = openssl-fips-test
SRCS = openssl-fips-test.c
CFLAGS += -Wall -std=gnu1x -O2 -D_FORTIFY_SOURCE=3
CFLAGS += $(shell pkg-config --cflags openssl)
INSTALL ?= install
LIBS = $(shell pkg-config --libs openssl)
OBJS = ${SRCS:.c=.o}

all: ${PROG}

${PROG}: ${OBJS}
	${CC} -o $@ ${OBJS} ${LIBS}

clean:
	rm ${OBJS} ${PROG}

install:
	${INSTALL} -Dm755 ${PROG} ${DESTDIR}/usr/bin/${PROG}

.DUMMY: clean
