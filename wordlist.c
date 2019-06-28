

#include <stdlib.h>
#include <stdio.h>
#include <string.h>


#define RADIX_BITS 10
#define RADIX (1<<RADIX_BITS)
#define ID_LENGTH_BITS 15
#define ITERATION_EXP_LENGTH_BITS 5
#define ID_EXP_LENGTH_WORDS 2 

#define bytes_to_words(n)  ( ( (n) * 8 + RADIX_BITS-1) / RADIX_BITS)
#define words_to_bytes(n)  ( ( (n) * RADIX_BITS ) / 8)

#define MAX_SHARE_COUNT 16
#define CHECKSUM_LENGTH_WORDS 3
#define DIGEST_LENGTH_BYTES 4
#define METADATA_LENGTH_WORDS 7
//(ID_EXP_LENGTH_WORDS + 2 + CHECKSUM_LENGTH_WORDS)
#define MIN_STRENGTH_BYTES 16
#define MIN_MNEMONIC_LENGTH_WORDS (METADATA_LENGTH_WORDS + bytes_to_words(MIN_STRENGTH_BYTES) )
#define BASE_ITERATION_COUNT 2500
#define ROUND_COUNT 4
#define SECRET_INDEX 255
#define DIGEST_INDEX 254

#define MAX_SECRET_LENGTH 256



typedef struct group_descriptor_struct {
	unsigned char threshold;
	unsigned char count;
} group_descriptor;



//////////////////////////////////////////////////
// encode mnemonic
unsigned int encode_mnemonic(
    const slip39_mnemonic *mnemonic,
    uint16_t *destination,
    uint32_t destination_length) {

	// pack the id, exp, group and member data into 4 10-bit words:
    // [id:1  5][exp:5][g_index:4][g_thresh*:4][g_count*:4][m_idx:4][m_thrsh*:4]    	
    // [w0:10][  w1:10][w2:10                      ][w3:10                     ]

	// change offset and clip group and member coordinate data
	uint16_t gt = (mnemonic->group_threshold -1) & 15;
	uint16_t gc = (mnemonic->group_count -1) & 15;
	uint16_t mi = (mnemonic->member_index) & 15;
	uint16_t mt = (mnemonic->member_threshold -1) & 15;

 	destination[0] = (mnemonic->identifier >> 5) & 1023;
 	destination[1] = ((mnemonic->identifier << 5) | mnemonic->iteration_exponent) & 1023;
 	destination[2] = ((mnemonic->group_index << 6) | (gt << 2) | (gc >> 2)) & 1023;
    destination[3] = ((gc << 8) | (mi << 4) | (mt)) & 1023;

    uint32_t words = toWords(mnemonic->value, mnemonic->value_length, destination+4, destination_length - METADATA_LENGTH_WORDS);
	rs1024_create_checksum(destination, words + METADATA_LENGTH_WORDS);	

	return words+METADATA_LENGTH_WORDS;
 }





//////////////////////////////////////////////////
// decode mnemonic
unsigned int decode_mnemonic(
	const uint16_t *mnemonic,
	uint32_t mnemonic_length,
	slip39_mnemonic *destination
) {
	if(mnemonic_length < MIN_MNEMONIC_LENGTH_WORDS) {
		printf("Invalid mnemonic- not enough mnemonic words.\n");
		return -1;
	}

	if( !rs1024_verify_checksum(mnemonic, mnemonic_length) ) {
		printf("Invalid mnemonic - checksum does not verify\n");
		return -1;
	}

	unsigned char gt = ((mnemonic[2] >> 2) & 15) +1;
	unsigned char gc = (((mnemonic[2]&3) << 2) | ((mnemonic[3]>>8)&3)) +1;

	if(gt > gc) {
		printf("Invalid mnemonic - group threshold cannot be larger than group count.\n");
	} 
	
	destination->identifier = mnemonic[0] << 5 | mnemonic[1] >> 5;
	destination->iteration_exponent = mnemonic[1] & 31;
	destination->group_index = mnemonic[2] >> 6;
	destination->group_threshold = gt;
	destination->group_count = gc; 
	destination->member_index = (mnemonic[3]>>4) & 15;
	destination->member_threshold = (mnemonic[3]&15) + 1;
	return fromWords(mnemonic+4, mnemonic_length - 7, destination->value, destination->value_length);
}

void print_hex(unsigned char *buffer, unsigned int length) {
	printf("0x");
	for(unsigned int i=0;i<length;++i) {
		if(i > 0 && i%32== 0) {
			printf("\n  ");
		}
		printf("%02x", buffer[i]);
	}
	printf("\n");	
}


void print_mnemonic(uint16_t *mnemonic, unsigned int mnemonic_length) {
	unsigned char value[256];

	uint16_t id;
	unsigned char exp, gi, gt, gc, mi, mt;

	unsigned int secret_length = decode_mnemonic(mnemonic, mnemonic_length, 
		&id, &exp, &gi, &gt, &gc, &mi, &mt, value, 256);

	for(unsigned int i=0;i< mnemonic_length; ++i) {
		printf("%s ", wordlist[ mnemonic[i]]);
	}
	printf("\n");
	printf("identifier: %d  exponent: %d\n", id, exp);
	printf("group index: %d  threshold: %d  count: %d\n", gi, gt, gc);
	printf("member index: %d  threshold: %d\n", mi, mt);
	print_hex(value, secret_length);
}

//////////////////////////////////////////////////
// generate mnemonics
//
int generate_mnemonics(
	unsigned char group_threshold,
	group_descriptor *groups, 
	unsigned char groups_length,
	unsigned char *master_secret,
	unsigned int master_secret_length,
	char *passphrase,
	unsigned int iteration_exponent,
	unsigned int *mnemonic_length,
	uint16_t *mnemonics,
	unsigned int buffer_size
) {
	uint16_t identifier = 0;
	randombytes((unsigned char *)(&identifier), 2);
	identifier = identifier & ((1<<15)-1);
	if(master_secret_length < MIN_STRENGTH_BYTES) {
		printf("The length of the master secret (%d bytes) must be at least %d bytes.\n", master_secret_length, MIN_STRENGTH_BYTES);
		return -1;
	}

	unsigned int share_length = METADATA_LENGTH_WORDS + bytes_to_words(master_secret_length);
	unsigned int total_shares = 0;

	for(unsigned char i=0; i<groups_length; ++i) {
		total_shares += groups[i].count;
		if( groups[i].threshold > groups[i].count ) {
			printf("The member theshold cannot exceed the member count.\n");
			return -1;
		}
		if( groups[i].threshold == 1 && groups[i].count > 1) {
			printf("Creating multiple member shares with member thrshold 1 is not allowed.\n");
			return -1;
		}
	}
	
	if(buffer_size < share_length * total_shares) {
		printf("Results buffer not large enough for that many shares.\n");
		return -1;
	}

	if(master_secret_length % 2 == 1) {
		printf("The length of the master secret in bytes must be an even number.\n");
		return -1;
	}

	for(unsigned char *p = (unsigned char *) passphrase; *p; p++) {
		if( (*p < 32) || (126 < *p) ) {
			printf("The passphrase must contain only printable ASCII characters: %s %d\n",passphrase, *p);
			return -1;
		}
	}

	if(group_threshold > groups_length) {
		printf("The group threshold cannot exceed the number of groups.\n");
		return -1;
	}
	
	unsigned char encrypted_master_secret[MAX_SECRET_LENGTH];

	encrypt(master_secret,master_secret_length,passphrase,iteration_exponent,identifier, encrypted_master_secret);

	unsigned char group_shares[MAX_SECRET_LENGTH * MAX_SHARE_COUNT];

	split_secret(group_threshold, groups_length, encrypted_master_secret, master_secret_length, group_shares);

	unsigned char *group_share = group_shares;

	uint16_t *mnemonic = mnemonics;
	unsigned int remaining_buffer = buffer_size;

 	unsigned int word_count = 0;
 	unsigned int share_count = 0;
 	
	for(unsigned char i=0; i<groups_length; ++i, group_share += master_secret_length) {
		unsigned char member_shares[MAX_SECRET_LENGTH*MAX_SHARE_COUNT];
		split_secret(groups[i].threshold, groups[i].count, group_share, master_secret_length, member_shares);

		unsigned char *share = member_shares;
		for(unsigned char j=0; j< groups[i].count; ++j, share += master_secret_length) {
			unsigned int words = encode_mnemonic(identifier, iteration_exponent, 
				i, group_threshold, groups_length,
				j, groups[i].threshold,
				share, 
				master_secret_length, 
				mnemonic, remaining_buffer);
			if(word_count == 0) {
				word_count = words;
			} else {
				if(word_count != words) {
					printf("Error - shares should be equal lengths.\n");
					return -1;
				}
			}
			remaining_buffer -= word_count;
			share_count++;
			mnemonic += word_count;
		}
	}

	// store the number of words in each share
	*mnemonic_length = word_count;
	
	// return the number of shares generated
	return share_count;
}


typedef struct {
	unsigned char group_index;
	unsigned char member_threshold;
	unsigned char count;
	unsigned char member_index[16];
	unsigned char *value[16];
} group_struct;


void print_group(group_struct *g, unsigned int secret_length) {
	printf("group index: %d  threshold: %d  count: %d\n", 
		g->group_index, g->member_threshold, g->count );
	for(unsigned char i=0; i<g->count; ++i) {
		printf("%d: ", g->member_index[i]);
		print_hex(g->value[i], secret_length);
	}
}


/////////////////////////////////////////////////
// combine_mnemonics
int combine_mnemonics(
	uint16_t **mnemonics,   // array of pointers to 10-bit words
	unsigned int mnemonics_words, // number of words in each share
	unsigned int mnemonics_shares,// total number of shares
	char *passphrase,             // passphrase to unlock master secret
	unsigned char *buffer,        // working space, and place to return secret
	int buffer_length             // total amount of working space
) {
	uint16_t identifier;
	unsigned char iteration_exponent;
	unsigned char group_threshold;
	unsigned char group_count;

	if(mnemonics_shares == 0) {
		printf("The list of mnemonics is empty.\n");
		return -1;
	}

	unsigned char next_group = 0;
	group_struct groups[16];
	
	unsigned char *next_share = buffer;
	int buffer_remaining = buffer_length;
	unsigned int secret_length = 0;

	for(unsigned int i=0; i<mnemonics_shares; ++i) {
		uint16_t id;
		unsigned char exp, gindex, gt, gc, mi, mt;
		int bytes = decode_mnemonic(mnemonics[i], mnemonics_words,
			&id, &exp, &gindex, &gt, &gc, &mi, &mt, next_share, buffer_remaining);
		if(bytes < 0) {
			printf("Decode mnemonic failed.\n");
			return -1;
		}

		// advance pointers into free buffer
		buffer_remaining -= bytes;
		unsigned char *value = next_share;
		secret_length = bytes;

		next_share += bytes;
		
		if( i == 0) {
			// on the first one, establish expected values for common metadata
			identifier = id;
			iteration_exponent = exp;
			group_count = gc;
			group_threshold = gt;
		} else {
			// on subsequent shares, check that common metadata matches
			if( id != identifier ||
				exp != iteration_exponent ||
				gt != group_threshold ||
				gc != group_count 
			) {
				printf("All identifiers, iteration exponents, group counts and group thresholds must match.\n");
				return -1;
			}
		}
		// sort shares sinto member groups
		unsigned char group_found = 0;
		for(unsigned char j=0; j<next_group; ++j) {		
			if(gindex == groups[j].group_index) {
				group_found = 1;
				if(mt != groups[j].member_threshold) {
					printf("All member shares must have the same member thresholds.\n");
					return -1;
				}
				for(unsigned char k=0; k<groups[j].count; ++k) {
					if(mi == groups[j].member_index[k]) {
						printf("Duplicate member indexes are not allowed.\n");
						return -1;
					}
				}
				groups[j].member_index[groups[j].count] = mi;
				groups[j].value[groups[j].count] = value;
				groups[j].count++;
			}
		}
	
		if(!group_found) {
			groups[next_group].group_index = gindex;
			groups[next_group].member_threshold = mt;
			groups[next_group].count =1;
			groups[next_group].member_index[0] = mi;
			groups[next_group].value[0] = value;
			next_group++;
		}
	}

	// here, all of the shares are unpacked into member groups. Now we go through each
	// group and recover the group secret, and then use the result to recover the 
	// master secret	
	unsigned char gx[16];
	unsigned char *gy[16];

	for(unsigned char i=0; i<next_group; ++i) {
		gx[i] = groups[i].group_index;
		if(groups[i].count < groups[i].member_threshold) {
			printf("Not enough shares to recover group secret.\n");
			return -1;
		}

		int recovery = recover_secret(groups[i].member_threshold, groups[i].member_index, groups[i].value, secret_length, next_share);
		
		if(recovery < 0) {
			printf("Failed to recover group secret.\n");
			return -1;
		}
		gy[i] = next_share;

		next_share += recovery;
	}
	
	int recovery = recover_secret(group_threshold, gx, gy, secret_length, next_share);

	if(recovery < 0) {
		printf("Failed to recover master secret.\n");
		return -1;
	}

	// decrypt copy the result to the beinning of the buffer supplied
	decrypt(next_share, secret_length, passphrase, iteration_exponent, identifier, buffer);

	// TODO: clean up scratch memory
	return secret_length;
}


void test_encrypt_decrypt() {
	char *string = "test test test.";
	char *password = "asdf";

	unsigned char encrypted[16];
	unsigned char decrypted[16];

	encrypt((unsigned char *)string, 16, password, 0, 1234, encrypted);
	decrypt(encrypted, 16, password, 0, 1234, decrypted);

	printf("%s\n", decrypted);
}

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

	//for(int i=0; i < shares; ++i) {
	//	for(unsigned int j=0; j<words_per_share; ++j) {
	//		printf("%s ", wordlist[mnemonics[i*words_per_share + j]]);
	//	}
	//	printf("\n\n");
	//}


	uint16_t* recovery_mnemonics[] = {
		// two from the first group
		mnemonics, mnemonics + words_per_share,
		// one from the second
		mnemonics + 3*words_per_share,
		// three from the third
		mnemonics + 6*words_per_share,
	    mnemonics + 5*words_per_share,
		mnemonics + 4*words_per_share,
	};

	//for(unsigned char i=0; i<3; ++i) {
	//	for(unsigned char j=0; j<4; ++j) {
	//		printf("%s ", wordlist[ recovery_mnemonics[i][j] ]);
	//	}
	//	printf("\n");
	//}
	int result = combine_mnemonics(recovery_mnemonics, words_per_share, 6, "", buffer, 1024);

	if(result < 0) {
		printf("Recovery failed.\n");
		exit(-1);
	}
	printf("%s\n", buffer);
}


void test_generate_combine1() {
	char *test = "abcdefghijklmnopqrstuvwxyz.";
	unsigned int secret_length = strlen(test)+1;

	uint16_t mnemonics[1024];
	unsigned char buffer[1024];
	unsigned int words_per_share = 0;
	
	group_descriptor groups[1] = {
		{1,1},
	};

	int shares = generate_mnemonics(1, groups, 1, (unsigned char *)test, secret_length, 
		"unchained", 0,
		&words_per_share, mnemonics, 1024);

	if(shares < 0) {
		printf("Fail: An error occurred during generation.\n");
		return;
	}	

	if(shares != 1) {
		printf("Fail: Expected 1 share.\n");
		return;
	}

	uint16_t* recovery_mnemonics[] = {
		mnemonics,
	};

	int result = combine_mnemonics(recovery_mnemonics, words_per_share, 1, "unchained", buffer, 1024);

	if(result < 0) {
		printf("Fail: Recovery failed.\n");
		return;
	}

	if(strcmp(test,buffer) != 0) {
		printf("Fail: recovered: ''%s' should be '%s'", buffer, test);
		return;
	}
	printf("Pass: %s\n", buffer);
}


void test_valid_mnemonic(void) {
	char *word_string = "duckling enlarge academic academic agency result length solution fridge kidney coal piece deal husband erode duke ajar critical decision keyboard";
    char *expected_result= "bb54aac4b89dc868ba37d9cc21b2cece";
	
    uint16_t words[20];
    unsigned char result[1024];
	
    int n = parse_words(word_string, words, 20);
	   
    if(n<0 || n>20) {
    	printf("invalid result from parse_words: %d\n", n);
    }

	for(int i=0; i<n; ++i) {
		printf("%s ", wordlist[ words[i]]);
	}
	printf("\n");
	
	uint16_t* recovery_mnemonics[] = {
		words,
	};

	int m = combine_mnemonics(recovery_mnemonics, n, 1, "TREZOR", result, 128);
	print_hex(result,m);
}


void test_multi(void) {
	char *shares[] = {
  		"eraser senior decision roster beard treat identify grumpy salt index fake aviation theater cubic bike cause research dragon emphasis counter",
	    "eraser senior ceramic snake clay various huge numb argue hesitate auction category timber browser greatest hanger petition script leaf pickup",
	    "eraser senior ceramic shaft dynamic become junior wrist silver peasant force math alto coal amazing segment yelp velvet image paces",
	    "eraser senior ceramic round column hawk trust auction smug shame alive greatest sheriff living perfect corner chest sled fumes adequate",
	    "eraser senior decision smug corner ruin rescue cubic angel tackle skin skunk program roster trash rumor slush angel flea amazing"
	};
	char *res = "7c3397a292a5941682d7a4ae2d898d11";
	uint16_t recovery[100];
	unsigned int n;
	unsigned char result[1024];
	
	for(int i=0;i<5;++i) {
		n = parse_words(shares[i],recovery + i * 20,20);
	}

	uint16_t *rc[] = {recovery,recovery+20,recovery+40,recovery+60,recovery+80};
	
	int m = combine_mnemonics(rc, n, 5, "TREZOR", result, 1024);
	if(m>0) {
		print_hex(result,m);	
	}
}

void setup(void) {
    precompute_gf256_exp_log_tables();		
}

/*
int main(int argc, char *argv[]) {

	setup();

	//test_toWords_fromWords();
	//test_gf256();
	//test_lagrange();
	//test_interpolation();

	//test_split_recover();

	//test_generate_combine1();
	//test_encrypt_decrypt();
	//test_valid_mnemonic();
	//test_round_function();
	//test_encrypt_function();
	test_multi();
}
*/