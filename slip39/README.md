# C Implementation for SLIP-0039

There has recently been a growing interest in applying Shamir's Secret-Sharing Scheme
to protecting and distributing the underlying secrets for cryptocurrency hierarchical
deterministic (HD) wallets. The folks over at Satoshi Labs have proposed an interoperable
standard for doing so:
[SLIP-0039: Shamir's Secret-Sharing for Mnemonic Codes](https://github.com/satoshilabs/slips/blob/master/slip-0039.md)

Along with the proposed specification, they also have provided a
[python reference implementation](https://github.com/trezor/python-shamir-mnemonic)
and a set of
[sest vectors](https://github.com/trezor/python-shamir-mnemonic/blob/master/vectors.json).

This branch intends to provide an implementation of the specification in C. Note that SLIP39
differs from standard implementations of Shamir Sharing in a couple of ways - it adds some
digest checking that allows you to give you some assurance that the result is correct at
the expense of a few bits of security, it has a two-level grouping scheme, etc. At its heart,
it ends up making more use of polynomical interpolation than other implementations do.

The file vectors_to_tests.js contains some javascript that uses the published test vectors
to produce C code that can be used to verify that the code implements the spec.

hazmat.c provides a side-channel attack resistant implementation of gf256 operations
32 elements at a time, with a couple of additional functions dealing with lagrange
polynomials and polynomial interpolation.

test_random.c implements some code to act as filler for random number generation when testing.
It is clearly not designed to be used in any real life application.

slip_encrypt.c implements the four-round fiestel network described in slip39, but it requires
pbkd2 and sha256 impementations, currently imported from openssl.

slip39_rs1024.c implements the 10-bit, three word Reed Solomon checksum described in slip39.

slip39_shamir.c implements the single level secret sharing scheme used by slip39. This includes
imbedding a digest into the shares which requires a sha256. Again this implementation relies
on openssl for sha256.

slip39_wordlists.c implements functions for converting byte buffers to wordlists and
and the encoding and decoding of slip39 words into 10-bit integers. the toWords and
fromWords functions do/check the appropriate left padding of bits described in slip39.
slip39_wordlist_english.h contains the actual word list used.

There are various and sundry test files that test key parts of the implementation. You can
build and run them all by building the make target 'check'.

There is also a quick and dirty command line. You can build it with the make target 'slip39'. Here
is a sample of running it to generate a share set and then combine some of those shares
back into the default secret 'totally secret!':
```bash
chris@rebma:~/projects/shamir/sss/slip39$ ./slip39 generate 2 2of3 3of5
research romp acrobat echo armed decrease slush random cubic miracle dive exchange biology strategy bulb idea shrimp likely machine starting
research romp acrobat email advocate academic gesture herd geology artist crystal liberty scandal smith amount costume endorse genuine steady have
research romp acrobat entrance beam fangs window bolt identify receiver large saver indicate view dive gesture believe salary prize laser
research romp beard eclipse closet jacket argue silver smirk garlic railroad tadpole wireless flame cover blessing worthy criminal penalty upgrade
research romp beard emerald always blanket calcium forecast photo picture election curly quarter coding equip beam always spray goat become
research romp beard envelope award presence adapt engage mustang language domestic ocean sympathy prisoner painting document username view mountain random
research romp beard exact chemical ruin away squeeze wrote remove skin hairy mouse syndrome royal easel airline ancestor famous favorite
research romp beard eyebrow cinema verify skunk oasis senior endless ting round ting sugar inherit sugar true image keyboard estimate
chris@rebma:~/projects/shamir/sss/slip39$ ./slip39 combine
research romp acrobat echo armed decrease slush random cubic miracle dive exchange biology strategy bulb idea shrimp likely machine starting
research romp acrobat email advocate academic gesture herd geology artist crystal liberty scandal smith amount costume endorse genuine steady have
research romp beard envelope award presence adapt engage mustang language domestic ocean sympathy prisoner painting document username view mountain random
research romp beard exact chemical ruin away squeeze wrote remove skin hairy mouse syndrome royal easel airline ancestor famous favorite
research romp beard eyebrow cinema verify skunk oasis senior endless ting round ting sugar inherit sugar true image keyboard estimate
totally secret!
chris@rebma:~/projects/shamir/sss/slip39$
```
