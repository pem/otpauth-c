#
# pem 2024-10-06
#
#

CC=gcc -std=c11

CCOPTS=-pedantic -Wall -Werror

OS=$(shell uname)

# On Linux you should normally have openssl installed where gcc
# will find the include files, but you can point to a specific
# place here. On the other platforms you will probably have to
# set it.
ifeq ($(OS),Linux)
CCDEFS=  # -I..somewhere.../include
endif
ifeq ($(OS),Darwin)
CCDEFS=  # -I..somewhere.../include
endif
ifeq ($(OS),SunOS)
CCDEFS=  # -I..somewhere.../include
endif
ifeq ($(OS),AIX)
CCDEFS=  # -I..somewhere.../include
endif

CFLAGS=-g $(CCOPTS) $(CCDEFS)
#CFLAGS=-O $(CCOPTS) $(CCDEFS)

# On Linux you will probably not need -L for the library path.
# For -l, at least -lcrypt is required.
# Depending on platform and how the openssl is built, it might have
# secondary dependencies, some combination of -lz, -lpthread, and -ldl .
ifeq ($(OS),Linux)
LDFLAGS= # -L...somewhere.../lib
LDLIBS=-lcrypto
endif
ifeq ($(OS),Darwin)
LDFLAGS= # -L...somewhere.../lib
LDLIBS=-lcrypto
endif
ifeq ($(OS),SunOS)
LDFLAGS= # -L...somewhere.../lib
LDLIBS=-lcrypto
endif
ifeq ($(OS),AIX)
LDFLAGS= # -L...somewhere.../lib
LDLIBS=-lcrypto
endif

PROG1=base32test
PROG2=otpauthtest

LIB=libotpauth.a

SRC=otpauth.c otpauth-uri.c base32.c

OBJ=$(SRC:%.c=%.o)

all:	$(PROG1) $(PROG2)

$(PROG1):	base32test.o $(LIB)

$(PROG2):	otpauthtest.o $(LIB)

$(LIB):	$(COBJ) $(OBJ)
	rm -f $(LIB)
	$(AR) qc $(LIB) $(COBJ) $(OBJ)
	ranlib $(LIB)

clean:
	$(RM) base32test.o otpauthtest.o $(OBJ) core

cleanall:	clean
	$(RM) $(PROG1) $(PROG2) $(LIB) make.deps

make.deps:
	gcc -MM $(CFLAGS) $(SRC) > make.deps

include make.deps
