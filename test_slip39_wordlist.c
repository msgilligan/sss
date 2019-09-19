#include "slip39.h"

uint8_t test_toWords_fromWords(void);
uint8_t test_lookups(void);

#include "slip39_wordlist_english.h"

uint8_t test_lookups(void) {
    uint8_t fail = 0;

    for(uint16_t i=0; i<1024; ++i) {
        int16_t j = lookup(wordlist[i]);
        if(i != j) {
            fail = 1;
        }
    }

    if(lookup("foobar") != -1) {
        fail = 1;
    }

    if(lookup("aaa") != -1) {
        fail = 1;
    }

    if(lookup("zzz") != -1) {
        fail = 1;
    }

    if(lookup("") != -1) {
        fail = 1;
    }

    return fail;
}

uint8_t test_toWords_fromWords(void) {
    uint8_t fail = 0;
    char *x = " abcdefghijklmnopqrstuvwxyz";
    uint16_t words[25];
    uint8_t results[30];

    int32_t w;

    for(uint8_t i=0; i<26; i+=2) {
        w = to_words((uint8_t *)x+i , strlen(x+i)+1, words, 25);
        from_words(words, w, results, 30);

        if(strcmp((char *)results,x+i) !=0) {
            printf("Fail: '%s' != '%s'\n", x+i, results);
            //return;
            for(unsigned char j=0;j<w;j++) {
                printf("%d ", words[j]);
            }
            printf("\n");
            fail = 1;
        }
    }

    return fail;
}

int main(void) {
    uint8_t fail =0;
    uint8_t t;

    t = test_lookups();
    fail = fail || t;
    printf("Test lookups: %s\n", t ? "fail" : "pass" );

    t = test_toWords_fromWords();
    fail = fail || t;
    printf("Test toWords and fromWords: %s\n", t ? "fail" : "pass" );

    return fail;
}
