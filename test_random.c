#include "slip39.h"

// Clearly not so random. Dont use outside of tests. 
static uint8_t b = 0;
int randombytes(void *bufv, size_t len) {
    uint8_t *buf = (uint8_t *) bufv;
    for(uint32_t i=0;i<len;++i) {
        buf[i] = b;
        b += 17;
    }
    return len;
}
