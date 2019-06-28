#ifndef GF256_INTERPOLATE_H
#define GF256_INTERPOLATE_H

#include "gf256.h"

// Lagrange Polynomials:
//                  n
//                 ---
// l_n_m(x,[x]) =  | |   ( x - x_i ) / ( x_m - x_i )
//               i != m      
//
// note that x_i != x_j for i != j

int16_t lagrange(
	uint8_t n,   // number of points to interpolate
	uint8_t m,   // index of this point
	const uint8_t *xi, // x coordinates of all points (array of size n)
	uint8_t x    // x coordinate to evaluate 
);


// Interpolate
// given a polynomial that goes through n points { (x_i, y_i) }
// calculate the value for y at a given x
//
// On success, this returns the length of the recovered secret. On failure,
// it returns -1.
int16_t interpolate(
	uint8_t n,       // number of points to interpolate
	const uint8_t* xi,     // x coordinates for points (array of length n)
	uint32_t yl, // length of y coordinate array 
	const uint8_t **yij,   // n arrays of yl bytes representing y values
	uint8_t x,       // x coordinate to interpolate
	uint8_t* result  // space for yl bytes of results
);

#endif
