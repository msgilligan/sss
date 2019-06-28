#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include "slip39.h"

int help(void);
int generate(int, char**, char*, char *);
int combine(char *);

int help(void) {
    printf("slip39 - generate or combine slip39 style shamir shared secrets.\n\n");
    printf("usage: slip39 combine {-p password}\n");
    printf("       slip39 generate {-p password} {-s secret} <threshold> k1ofn1 k2ofn2 ...\n");
    // slip39cli generate 5 2of3 2of3 1of1 -p password    
    // slip39cli combine -p password

    return -1;
}

void print_words(uint16_t *, int32_t);

void print_words(uint16_t *words, int32_t count) {
    if(count > 0) {
        printf("%s", slip39_word(words[0]));
        for(int32_t i=1; i<count; ++i) {
            printf(" %s", slip39_word(words[i]));
        }
    }
    printf("\n");
}

int generate(int arg_count, char **args, char *password, char *secret) {
    group_descriptor groups[arg_count -1];
    int group_threshold;
    int i;
    int group_count = arg_count - 1;

    sscanf(args[0], "%d", &group_threshold);
    for(i=0;i<arg_count-1;++i) {
        int gt, gc;
        sscanf(args[i+1], "%dof%d", &gt, &gc);
        groups[i].threshold = gt;
        groups[i].count = gc;
        groups[i].passwords = NULL;
    }


    if(!password) {
        password = "";
    }

    if(!secret) {
        secret = "totally secret!";
    }

    //printf("generate password='%s' secret='%s' threshold=%d count=%d\n", password, secret, group_threshold, group_count);

    //for(i=0;i<group_count;++i) {
    //    printf("  group %d: %d of %d\n",i,groups[i].threshold, groups[i].count);
    //}

    uint16_t mnemonics[1024];
    uint32_t mnemonic_length = 0;
    int count;
    count = generate_mnemonics(group_threshold, groups, group_count, 
        (uint8_t *)secret, strlen(secret)+1, password, 0, &mnemonic_length, mnemonics, 1024);

    //printf("%d\n", count);
    if(count < 0) {
        return count;
    }
    
    uint16_t *mnem = mnemonics;
    for(i=0; i<count; ++i, mnem += mnemonic_length) {
        print_words(mnem, mnemonic_length);
    }
    
    return 0;
}

int combine(char *password) {
    //printf("combine password='%s'\n", password);

    //printf("\n");       

    if(!password) {
        password = "";
    }

    uint16_t mnemonics[1024];
    uint32_t remaining = 1024;

    uint16_t *mnem = &(mnemonics[0]);
    
    char *line = NULL;
    size_t size;
    int read = 0;

    
    uint32_t mnemonic_length = 0;
    uint32_t mnemonic_count = 0;
    const uint16_t *mnems[32];
    
    while ((read = getline(&line, &size, stdin)) != -1) {
        int word_count = parse_words(line, mnem, remaining);
        if(word_count > 0) {
            mnems[mnemonic_count++] = mnem;

            mnem += word_count;
            mnemonic_length = word_count;
            remaining -= word_count;
        }    
    }
    
    if (line)
        free(line);

    uint8_t output[256];
    int count = combine_mnemonics(mnems, mnemonic_length, mnemonic_count, password, NULL, output, 256);

    if(count < 0) {
        printf("%d", count);
        return count;
    }
    printf("%s\n", output);
    
    return 0;
}


int main(int argc, char **argv) {

    int i=1;

    if(argc < 2) {
        return help();
    }  
    
    char *password = NULL;
    char *secret = NULL;
    char *command = NULL;
    char *command_args[argc-2];
    int c = 0;

    command = argv[1];
    i = 2;


    // parse command line arguments
    while(i<argc) {
        if(strcmp(argv[i], "-p" ) == 0) {
            password = argv[i+1];
            i+=2;
        } else if(strcmp(argv[i], "-s") == 0) {
            secret = argv[i+1];
            i+=2;
        } else {
            command_args[c++] = argv[i++];
        }
        
    }    

    if(strcmp("combine", command) == 0) {
        if(c > 0 || secret) {
            return help();
        }
        return combine(password);
    } else if(strcmp("generate", command) == 0) {
        if(c < 2) {
            return help();
        }
        
        return generate(c, command_args, password, secret);
    } else {
        return help();
    }
}
