#include "slip39.h"
uint8_t test_split_recover(void);

uint8_t test_split_recover(void) {
    uint8_t fail = 0;
    // secret can only be 32 bytes long...
    char *test = "The quick brown fox jumped ove"; //r the lazy dog.";

    uint8_t shares[512];
    uint8_t secret[50];

    uint32_t secret_length = strlen(test)+1;

    int8_t share_count = split_secret(3, 10, (uint8_t *)test, secret_length, shares);

    if(share_count != 10) {
        printf("expected share_count to be 10\n");
        fail = 1;
    }

    uint8_t *sh[10];
    for(uint8_t i=0;i<10;++i) {
        sh[i] = shares + i*secret_length;
    }

    for(uint8_t i=0;i<8;++i) {
        for(uint8_t j=i+1;j<9;++j) {
            for(uint8_t k=j+1; k<10;++k) {
                uint8_t x[] = {j, i, k};
                const uint8_t *y[] = {sh[j], sh[i], sh[k]};

                int recovery = recover_secret(3, x, y, secret_length, secret);

                if(recovery < 0 || strcmp((char *)test, (char *)secret) != 0) {
                    printf("secret recovery failed\n");
                    fail = 1;
                }
            }
        }
    }

    return fail;
}

int main(void) {
    uint8_t fail = 0;
    uint8_t t;

    t = test_split_recover();
    fail = fail || t;
    printf("test split and recover: %s\n", t ? "fail" : "pass" );

    return fail;
}