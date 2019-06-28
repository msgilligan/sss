
#include "gf256.h"
#include <stdio.h>

#define ASSERT(x, args...) if(!(x)) {printf(args); fail=1;}

uint8_t test_exp_log_inverses(void);
uint8_t test_additive_inverses(void);
uint8_t test_additive_identity(void);
uint8_t test_multiplicitive_inverses(void);
uint8_t test_multiplicitive_identity(void);

uint8_t test_exp_log_inverses(void) {
    uint8_t fail = 0;

    for(uint16_t i=1; i<256; i++) {
        uint8_t a = i;
        ASSERT(gf256_exp(gf256_log(a)) == a, "Exp as inverse of log failed for %d.", a)
    }

    printf("Exp/Log Inverse: %s\n", fail ? "fail" : "pass");
    return fail;
}

uint8_t test_additive_inverses(void) {
    uint8_t fail = 0;

    for(uint16_t i=0; i<256; i++) {
        uint8_t a = i;
        ASSERT(gf256_add(a,a)==0, "Additive inverse property failed for %d.\n", a)
    }

    printf("Additive Inverse: %s\n", fail ? "fail" : "pass");
    return fail;
}

uint8_t test_additive_identity(void) {
    uint8_t fail = 0;

    for(uint16_t i=0; i<256; i++) {
        uint8_t a = i;
        ASSERT(gf256_add(a,0)==a, "Additive identity property failed for %d.\n", a)
        ASSERT(gf256_add(0,a)==a, "Additive identity property failed for %d.\n", a)
    }

    printf("Additive Identity: %s\n", fail ? "fail" : "pass");
    return fail;
}

uint8_t test_multiplicitive_inverses(void) {
    uint8_t fail = 0;

    for(uint16_t i=1; i<256; i++) {
        uint8_t a = i;
        uint8_t b = gf256_div(1,a);

        ASSERT(gf256_div(a,a)==1, "Multiplicitive inverse property failed for %d.", a)
        ASSERT(gf256_mult(a,b)==1, "Multiplicitive inverse property failed for %d.", a)
        ASSERT(gf256_mult(b,a)==1, "Multiplicitive inverse property failed for %d.", a)
    }

    printf("Multiplicitive Inverse: %s\n", fail ? "fail" : "pass");
    return fail;
}

uint8_t test_multiplicitive_identity(void) {
    uint8_t fail = 0;

    for(uint16_t i=1; i<256; i++) {
        uint8_t a = i;
        ASSERT(gf256_mult(a,1)==a, "Multiplicitive identity property failed for %d.", a)
        ASSERT(gf256_mult(1,a)==a, "Multiplicitive identity property failed for %d.", a)
        ASSERT(gf256_div(a,1)==a, "Multiplicitive identity property failed for %d.", a)
    }

    printf("Multiplicitive Identity: %s\n", fail ? "fail" : "pass");
    return fail;
}

int main(void) {
    uint8_t fail = 0;

    fail = test_exp_log_inverses() || fail;
    fail = test_additive_inverses() || fail;
    fail = test_additive_identity() || fail;
    fail = test_multiplicitive_inverses() || fail;
    fail = test_multiplicitive_identity() || fail;

    return fail;
}