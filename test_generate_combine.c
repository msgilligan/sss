#include "slip39.h"

void test_generate_combine() {
    char *test = "abcdefghijklmnopqrstuvwxyz.";
    unsigned int secret_length = strlen(test)+1;

    uint16_t mnemonics[1024];
    unsigned char buffer[1024];
    unsigned int words_per_share = 0;

    group_descriptor groups[3] = {
        {2,3},
        {1,1},
        {3,5}
    };

    int shares = generate_mnemonics(3, groups, 3, (unsigned char *)test, secret_length,
        "", 0,
        &words_per_share, mnemonics, 1024);

    if(shares < 0) {
        printf("An error occurred during generation.\n");
        exit(-1);
    }

    for(int i=0; i < shares; ++i) {
        print_mnemonic(mnemonics + i*words_per_share, words_per_share);
        printf("\n");
    }


    const uint16_t* recovery_mnemonics[] = {
        // two from the first group
        mnemonics, mnemonics + words_per_share,
        // one from the second
        mnemonics + 3*words_per_share,
        // three from the third
        mnemonics + 6*words_per_share,
        mnemonics + 5*words_per_share,
        mnemonics + 4*words_per_share,
    };

    int result = combine_mnemonics(recovery_mnemonics, words_per_share, 6, "", buffer, 1024);

    if(result < 0) {
        printf("Recovery failed.\n");
        exit(-1);
    }
    printf("%s\n", buffer);
}

int main() {
    test_generate_combine();
}