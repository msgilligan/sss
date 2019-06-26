CFLAGS += -g -O2 -m64 -std=c99 -pedantic \
	-Wall -Wshadow -Wpointer-arith -Wcast-qual -Wformat -Wformat-security \
	-Werror=format-security -Wstrict-prototypes -Wmissing-prototypes \
	-D_FORTIFY_SOURCE=2 -fPIC -fno-strict-overflow
SRCS = hazmat.c randombytes.c sss.c tweetnacl.c
OBJS := ${SRCS:.c=.o}

all: libsss.a

libsss.a: randombytes/librandombytes.a $(OBJS)
	$(AR) -rcs libsss.a $^

randombytes/librandombytes.a:
	$(MAKE) -C randombytes librandombytes.a

# Force unrolling loops on hazmat.c
hazmat.o: CFLAGS += -funroll-loops

%.out: %.o randombytes/librandombytes.a
	$(CC) -o $@ $(CFLAGS) $(LDFLAGS) $^ $(LOADLIBES) $(LDLIBS)
	$(MEMCHECK) ./$@

test_hazmat.out: $(OBJS)
test_sss.out: $(OBJS)

tests.c: vectors_to_tests.js vectors.json
	node vectors_to_tests.js > tests.c

test.o: test.c

wordlist.o: wordlist.c

tests: wordlist.o tests.o
	gcc wordlist.o tests.o -o tests -l crypto


gf256.o: gf256.c gf256.h

test_gf256.o: test_gf256.c gf256.h

test_gf256: test_gf256.o gf256.o
	gcc $^ -o $@
	./$@

.PHONY: check
check: test_hazmat.out test_sss.out

.PHONY: clean
clean:
	$(MAKE) -C randombytes $@
	$(RM) *.o *.gch *.a *.out
