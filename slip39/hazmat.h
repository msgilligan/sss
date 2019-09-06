/*
 * Low level API for Daan Sprenkels' Shamir secret sharing library
 * Copyright (c) 2017 Daan Sprenkels <hello@dsprenkels.com>
 *
 * Usage of this API is hazardous and is only reserved for beings with a
 * good understanding of the Shamir secret sharing scheme and who know how
 * crypto code is implemented. If you are unsure about this, use the
 * intermediate level API. You have been warned!
 */


#ifndef HAZMAT_H
#define HAZMAT_H

#include <inttypes.h>
#include "slip39.h"

void
hazmat_lagrange_basis(uint8_t *values,
                   uint8_t n,
                   const uint8_t *xc,
                   uint8_t x);


int16_t
interpolate(
    uint8_t n,           // number of points to interpolate
    const uint8_t* xi,   // x coordinates for points (array of length n)
    uint32_t yl,         // length of y coordinate array
    const uint8_t **yij, // n arrays of yl bytes representing y values
    uint8_t x,           // x coordinate to interpolate
    uint8_t* result      // space for yl bytes of results
);

//void
//sss_interpolate(uint8_t *values,
//                uint8_t n,
//                const uint8_t *xc,
//                const uint8_t **y,  // n sets of 32
//                uint8_t x);


#endif /* HAZMAT_H */
