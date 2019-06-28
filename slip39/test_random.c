#include "slip39.h"

// Clearly not so random. Dont use outside of tests. 
static uint8_t b = 0;
void randombytes(uint8_t *buf, uint32_t len) {
    for(uint32_t i=0;i<len;++i) {
        buf[i] = b;
        b += 17;
    }
}
