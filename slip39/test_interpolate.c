#include "hazmat.h"
#include <stdio.h>

uint8_t test_lagrange_orthogonality(void);
uint8_t test_lagrange_zero_one_uniqueness(void);
uint8_t test_interpolation(void);
uint8_t test_simple_interpolation(void);

int16_t lagrange(
    uint8_t n,   // number of points to interpolate
    uint8_t m,   // index of this point
    const uint8_t *xi, // x coordinates of all points (array of size n)
    uint8_t x    // x coordinate to evaluate
) {
    uint8_t values[n];

    hazmat_lagrange_basis(values, n, xi, x);

    return values[m];
}


uint8_t test_lagrange_orthogonality(void) {
    uint8_t fail = 0;

    uint8_t xi[3];

    for(int16_t i=0; i<16; ++i) {
        xi[0] = i;
        for(int16_t j=128; j<144; ++j) {
            xi[1] = j;
            for(int16_t k=250; k<256; ++k) {
                xi[2] = k;

                // Test the essential orthogonality property of the
                // lagrange polynomials with three parameters
                if(
                    lagrange(3,0,xi,i) != 1 ||
                    lagrange(3,0,xi,j) != 0 ||
                    lagrange(3,0,xi,k) != 0 ||

                    lagrange(3,1,xi,i) != 0 ||
                    lagrange(3,1,xi,j) != 1 ||
                    lagrange(3,1,xi,k) != 0 ||

                    lagrange(3,2,xi,i) != 0 ||
                    lagrange(3,2,xi,j) != 0 ||
                    lagrange(3,2,xi,k) != 1
                ) {
                    printf("lagrange failure %d %d %d\n", i, j, k);
                    fail = 1;
                }
            }
        }
    }

    return fail;
}

uint8_t test_lagrange_zero_one_uniqueness(void) {
    uint8_t fail = 0;
    uint8_t xi[2];

    for(int16_t i=0; i<16; ++i) {
        xi[0] = i;
        for(int16_t j=16; j<32; ++j) {
            xi[1] = j;
            // For two parameter lagrange polynomials, test to see that
            // zero one results do not result unless x in [xi]
            for(int16_t l=0;l<256;++l) {
                if( l!=i && l!=j &&
                    ( lagrange(2,0,xi,l) == 0 ||
                      lagrange(2,1,xi,l) == 0 ||
                      lagrange(2,0,xi,l) == 1 ||
                      lagrange(2,1,xi,l) == 1
                    )
                ) {
                    printf("lagrange failure 2 %d %d %d\n", i, j, l);
                    fail = 1;
                }
            }
        }
    }
    return fail;
}


uint8_t test_simple_interpolation(void) {
    uint8_t fail = 0;
    uint8_t x[] = { 1, 10 };
    uint8_t y0[] = { 1 };
    uint8_t y1[] = { 10 };
    const uint8_t *y[] = {y0, y1};

    uint8_t yr[256];

    // Interpolate the entire range of the polynomial
    for(uint8_t i=0; i<255; ++i) {
        interpolate(2,x,1,y,i,yr+i);
    }

    for(uint8_t i=0; i<255; ++i) {
        if(yr[i] != i) {
            printf("simple interpolation failure %d %d\n", i, yr[i]);
            fail = 1;
        }
    }
    return fail;
}

uint8_t test_interpolation(void) {
    uint8_t fail = 0;
    uint8_t x[] = { 0, 1 };
    uint8_t y0[] = { 1 };
    uint8_t y1[] = { 2 };
    const uint8_t *y[] = {y0, y1};
    uint8_t tx[] = { 0, 0 };
    uint8_t res[] = {0};

    uint8_t yr[256];
    const uint8_t *ty[] = { yr+0, yr+1 };

    // Interpolate the entire range of the polynomial
    for(uint8_t i=0; i<255; ++i) {
        interpolate(2,x,1,y,i,yr+i);
    }

    // pick any two points on the curve
    for(uint8_t j = 0; j<100; ++j) {
        for(uint8_t k = j+1; k<101; ++k) {
            tx[0] = j;
            tx[1] = k;
            ty[0] = yr + j;
            ty[1] = yr + k;
            // make sure that interpolating a curve through those
            // tow points has the same x=0 value
            interpolate(2,tx,1,ty,0,res);
            if(res[0] != 1) {
                printf("interpolation failure %d %d %d\n",j,k,res[0]);
                fail = 1;
            }
        }
    }

    return fail;
}


int main(void) {
    uint8_t fail = 0;
    uint8_t t;


    t = test_lagrange_orthogonality();
    fail = fail || t;
    printf("test lagrage orthogonality: %s\n", t ? "fail" : "pass" );

    t = test_lagrange_zero_one_uniqueness();
    fail = fail || t;
    printf("test lagrage zeros and ones: %s\n", t ? "fail" : "pass" );

    t = test_simple_interpolation();
    fail = fail || t;
    printf("test simple interpolation: %s\n", t ? "fail" : "pass" );
/*
    t = test_interpolation();
    fail = fail || t;
    printf("test interpolation: %s\n", t ? "fail" : "pass" );
*/
    return fail;
}
