#ifndef GF256_H
#define GF256_H

#include <stdint.h>

uint8_t gf256_log(uint8_t a);
uint8_t gf256_exp(uint8_t a);
uint8_t gf256_add(uint8_t a, uint8_t b);
uint8_t gf256_mult(uint8_t a, uint8_t b);
uint8_t gf256_div(uint8_t a, uint8_t b);

#endif