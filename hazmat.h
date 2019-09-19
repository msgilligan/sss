/*
 * Low level API for Daan Sprenkels' Shamir secret sharing library
 * Copyright (c) 2017 Daan Sprenkels <hello@dsprenkels.com>
 *
 * Usage of this API is hazardous and is only reserved for beings with a
 * good understanding of the Shamir secret sharing scheme and who know how
 * crypto code is implemented. If you are unsure about this, use the
 * intermediate level API. You have been warned!
 */


#ifndef sss_HAZMAT_H_
#define sss_HAZMAT_H_

#include <inttypes.h>


#define sss_KEYSHARE_LEN 33 /* 1 + 32 */


/*
 * One share of a cryptographic key which is shared using Shamir's
 * the `sss_create_keyshares` function.
 */
typedef uint8_t sss_Keyshare[sss_KEYSHARE_LEN];


/*
 * Share the secret given in `key` into `n` shares with a treshold value given
 * in `k`. The resulting shares are written to `out`.
 *
 * The share generation that is done in this function is only secure if the key
 * that is given is indeed a cryptographic key. This means that it should be
 * randomly and uniformly generated string of 32 bytes.
 *
 * Also, for performance reasons, this function assumes that both `n` and `k`
 * are *public* values.
 *
 * If you are looking for a function that *just* creates shares of arbitrary
 * data, you should use the `sss_create_shares` function in `sss.h`.
 */
void sss_create_keyshares(sss_Keyshare *out,
                          const uint8_t key[32],
                          uint8_t n,
                          uint8_t k);


/*
 * Combine the `k` shares provided in `shares` and write the resulting key to
 * `key`. The amount of shares used to restore a secret may be larger than the
 * threshold needed to restore them.
 *
 * This function does *not* do *any* checking for integrity. If any of the
 * shares not original, this will result in an invalid resored value.
 * All values written to `key` should be treated as secret. Even if some of the
 * shares that were provided as input were incorrect, the resulting key *still*
 * allows an attacker to gain information about the real key.
 *
 * This function treats `shares` and `key` as secret values. `k` is treated as
 * a public value (for performance reasons).
 *
 * If you are looking for a function that combines shares of arbitrary
 * data, you should use the `sss_combine_shares` function in `sss.h`.
 */
void sss_combine_keyshares(uint8_t key[32],
                           const sss_Keyshare *shares,
                           uint8_t k);



#include <inttypes.h>
#include "slip39.h"

/*
 * calculate the lagrange basis coefficients for the lagrange polynomial
 * defined byt the x coordinates xc at the value x.
 *
 * inputs: values: pointer to an array to write the values
 *         n: number of points - length of the xc array, 0 < n <= 32
 *         xc: array of x components to use as interpolating points
 *         x: x coordinate to evaluate lagrange polynomials at
 *
 * After the function runs, the values array should hold data satisfying
 * the following:
 *                ---     (x-xc[j])
 *   values[i] =  | |   -------------
 *              j != i  (xc[i]-xc[j])
 */
void
hazmat_lagrange_basis(uint8_t *values,
                   uint8_t n,
                   const uint8_t *xc,
                   uint8_t x);

/**
 * safely interpolate the polynomial going through
 * the points (x0 [y0_0 y0_1 y0_2 ... y0_31]) , (x1 [y1_0 ...]), ...
 *
 * where
 *   xi points to [x0 x1 ... xn-1 ]
 *   y contains an array of pointers to 32-bit arrays of y values
 *   y contains [y0 y1 y2 ... yn-1]
 *   and each of the yi arrays contain [yi_0 yi_i ... yi_31].
 *
 * returns: on success, the number of bytes written to result
 *          on failure, a negative error code
 *
 * inputs: n: number of points to interpolate
 *         xi: x coordinates for points (array of length n)
 *         yl: length of y coordinate arrays
 *         yij: array of n pointers to arrays of length yl
 *         x: coordinate to interpolate at
 *         result: space for yl bytes of interpolate data
 */
int16_t
interpolate(
    uint8_t n,           // number of points to interpolate
    const uint8_t* xi,   // x coordinates for points (array of length n)
    uint32_t yl,         // length of y coordinate array
    const uint8_t **yij, // n arrays of yl bytes representing y values
    uint8_t x,           // x coordinate to interpolate
    uint8_t* result      // space for yl bytes of results
);

#endif /* sss_HAZMAT_H_ */
