#include "gf256.h"

//////////////////////////////////////////////////
// gf256 operations
//
// Addition and subtraction oar the same thing.
// GF256     | Unsigned Char Representation
// ----------+--------------------------------
// a + b     |  a ^ b
// a - b     |  a ^ b
//
// for a,b !=0
// a * b     |  exp[ (log[a] + log[b]) % 256 ]
// a / b     |  exp[ (log[a] - log[b]) % 256 ]

static uint8_t initialized = 0;
static uint8_t gf256_exp_table[255];
static uint8_t gf256_log_table[256];

void precompute_gf256_exp_log_tables(void) {
	int i;
	unsigned int poly = 1;
	
	gf256_log_table[0] = 0; // should never look this up!
	
	for(i=0;i<255;++i) {
		gf256_exp_table[i] = poly;
		gf256_log_table[poly] = i;

		poly = (poly<<1) ^ poly;
		if(poly & 0x100) {
			poly = poly ^ 0x11B;
		}
	}
	initialized = 1;
}

uint8_t gf256_log(uint8_t a) {
	if(!initialized) {
		precompute_gf256_exp_log_tables();
	}
	return gf256_log_table[a];
}

uint8_t gf256_exp(uint8_t a) {
	if(!initialized) {
		precompute_gf256_exp_log_tables();
	}
	return gf256_exp_table[a];
}

uint8_t gf256_add(uint8_t a, uint8_t b) {
	return a ^ b;
}

uint8_t gf256_mult(uint8_t a, uint8_t b) {
	if(!initialized) {
		precompute_gf256_exp_log_tables();
	}

	if(a==0 || b==0) {
		return 0;
	}
	
	int la = gf256_log(a);
	int lb = gf256_log(b);
	int e = (la + lb) % 255;
	return gf256_exp(e);
}

uint8_t gf256_div(uint8_t a, uint8_t b) {
	if(!initialized) {
		precompute_gf256_exp_log_tables();
	}

	if(a==0) {
		return 0;
	}

	int la = gf256_log(a);
	int lb = gf256_log(b);
	int e = (255 + la - lb) % 255;
	return gf256_exp(e);
}
