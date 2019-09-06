CFLAGS += -g -O2 -m64 -std=c99 -pedantic \
	-Wall -Wshadow -Wpointer-arith -Wcast-qual -Wformat -Wformat-security \
	-Werror=format-security -Wstrict-prototypes -Wmissing-prototypes \
	-D_FORTIFY_SOURCE=2 -fPIC -fno-strict-overflow

SRCS = slip39_encrypt.c slip39_rs1024.c \
       slip39_shamir.c slip39_wordlist.c slip39_mnemonics.c hazmat.c

OBJS := ${SRCS:.c=.o}

all: libslip39.a

libslip39.so: libslip39.so
	$(CC) -shared $(CFLAGS) $^ -o $@

libslip39.a: ../randombytes/librandombytes.a $(OBJS)
	$(AR) -rcs $@ $^

../randombytes/librandombytes.a:
	$(MAKE) -C ../randombytes librandombytes.a

slip39_tests.c: vectors_to_tests.js vectors.json
	node vectors_to_tests.js > slip39_tests.c

slip39_tests.o: slip39_tests.c

slip39_tests.out: slip39_tests.o hazmat.o slip39_wordlist.o slip39_rs1024.o \
     slip39_shamir.o slip39_mnemonics.o test_random.o slip39_encrypt.o
	$(CC) -o $@ $(CFLAGS) $(LDFLAGS) $^ -l crypto
	$(MEMCHECK) ./$@

#gf256%.o: gf256&%.c hazmat.h gf256%.h
#	$(CC) -o $@ $(CFLAGS) $(LDFLAGS) $<

test_interpolate.o: test_interpolate.c

test_interpolate.out: hazmat.o test_interpolate.o
	$(CC) -o $@ $(CFLAGS) $(LDFLAGS) $^ $(LOADLIBES) $(LDLIBS)
	$(MEMCHECK) ./$@

test_slip39_wordlist.o: slip39.h test_slip39_wordlist.c

slip39_wordlist.o: slip39.h slip39_wordlist.c slip39_wordlist_english.h

test_slip39_wordlist.out: test_slip39_wordlist.o slip39_wordlist.o
	$(CC) -o $@ $(CFLAGS) $(LDFLAGS) $^ $(LOADLIBES) $(LDLIBS)
	$(MEMCHECK) ./$@

test_random.o: test_random.c

test_slip39_shamir.o: test_slip39_shamir.c slip39.h

slip39_shamir.o: slip39_shamir.c slip39.h

test_slip39_shamir.out: test_slip39_shamir.o slip39_shamir.o hazmat.o test_random.o
	gcc $^ -o $@ -l crypto
	./$@


slip39_encrypt.o: slip39_encrypt.c slip39.h

test_slip39_encrypt.out: test_slip39_encrypt.o slip39_encrypt.o
	gcc $^ -o $@ -l crypto
	./$@


test_generate_combine.o: test_generate_combine.c

test_generate_combine.out: test_generate_combine.o hazmat.o slip39_wordlist.o \
     slip39_rs1024.o slip39_shamir.o slip39_mnemonics.o slip39_encrypt.o ../randombytes/librandombytes.a
	$(CC) -o $@ $(CFLAGS) $(LDFLAGS) $^ $(LOADLIBES) $(LDLIBS) -l crypto
	$(MEMCHECK) ./$@

slip39: slip39_cli.c libslip39.a ../randombytes/librandombytes.a
	$(CC) -o $@ $(CFLAGS) $(LDFLAGS) $^ $(LOADLIBES) $(LDLIBS) -l crypto

check: test_interpolate.out test_slip39_wordlist.out \
    test_slip39_shamir.out test_slip39_encrypt.out test_generate_combine.out slip39_tests.out

.PHONY: check check_slip39

.PHONY: clean
clean:
	$(MAKE) -C ../randombytes $@
	$(RM) *.o *.gch *.a *.out
