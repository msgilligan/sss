
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "wordlist_english.h"

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

//////////////////////////////////////////////////
// rs1024 checksum functions

unsigned int generator[] = {
	0x00E0E040,
    0x01C1C080,
    0x03838100,
    0x07070200,
    0x0E0E0009,
    0x1C0C2412,
    0x38086C24,
    0x3090FC48,
    0x21B1F890,
    0x03F3F120,	 	
};

const unsigned short customization[] = {
	's', 'h', 'a', 'm', 'i', 'r',
};


// We need 30 bits of checksum to get 3 words worth (CHECKSUM_LENGTH_WORDS)
unsigned int rs1024_polymod(
	unsigned short *values,    // values - 10 bit words
	unsigned int values_length // number of entries in the values array
) {
	// there are a bunch of hard coded magic numbers in this
	// that would have to be changed if the value of CHECKSUM_LENGTH_WORDS
	// were to change.

	// unsigned ints are assumed to be 32 bits, which is enough to hold
	// CHECKSUM_LENGTH_WORDS * RADIX_BITS
	unsigned int chk = 1;

	// initialize with the customization string
	for(unsigned int i=0; i<6; ++i) {
		// 20 = (CHESUM_LENGTH_WORDS - 1) * RADIX_BITS
		unsigned int b = chk >> 20;
		// 0xFFFFF = (1 << ((CHECKSUM_LENGTH_WORDS-1)*RADIX_BITS)) - 1
		// 10 = RADIX_BITS
		chk = ((chk & 0xFFFFF) << 10 ) ^ customization[i];
		for(unsigned int j=0; j<10; ++j, b>>=1) {
			chk ^= generator[j] * (b&1);
		}		
	}

	// continue with the values
	for(unsigned int i=0; i<values_length; ++i) {
		unsigned int b = chk >> 20;
		chk = ((chk & 0xFFFFF) << 10 ) ^ values[i];
		for(unsigned int j=0; j<10; ++j, b>>=1) {
			chk ^= generator[j] * (b&1);
		}
	}

	return chk;
}


void rs1024_create_checksum(
	unsigned short *values, // data words (10 bit)
	unsigned int n          // length of the data array, including three checksum word 
) {
	values[n-3] = 0;
	values[n-2] = 0;
	values[n-1] = 0;

	unsigned int polymod = rs1024_polymod(values, n) ^ 1;

	values[n-3] = (polymod >> 20) & 1023;
	values[n-2] = (polymod >> 10) & 1023;
	values[n-1] = (polymod ) & 1023;
}				


unsigned int rs1024_verify_checksum(
	unsigned short *values,  // data words
	unsigned int n           // lenght of the data array
) {
    return rs1024_polymod(values, n) == 1;
}

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
unsigned char gf256_exp[255];
unsigned char gf256_log[256];

void precompute_gf256_exp_log_tables(void) {
	int i;
	unsigned int poly = 1;
	
	gf256_log[0] = 0; // should never look this up!
	
	for(i=0;i<255;++i) {
		gf256_exp[i] = poly;
		gf256_log[poly] = i;

		poly = (poly<<1) ^ poly;
		if(poly & 0x100) {
			poly = poly ^ 0x11B;
		}
	}
}

unsigned char gf256_add(unsigned char a, unsigned char b) {
	return a ^ b;
}

unsigned char gf256_mult(unsigned char a, unsigned char b) {
	if(a==0 || b==0) {
		return 0;
	}
	
	int la = gf256_log[a];
	int lb = gf256_log[b];
	int e = (la + lb) % 255;
	return gf256_exp[e];
}

unsigned char gf256_div(unsigned char a, unsigned char b) {
	if(a==0) {
		return 0;
	}

	int la = gf256_log[a];
	int lb = gf256_log[b];
	int e = (255 + la - lb) % 255;
	return gf256_exp[e];
}


// Lagrange Polynomials:
//                 n
//                ---
// pn_m(x,[x]) =  | |   ( x - x_i ) / ( x_m - x_i )
//               i != m      

//                    n
//                   ---
// log pn_m(x,[x]) = >    log(x - x_i) - log(x_m - x_i)
//                   ---
//                 i != m

// note that x_i != x_j for i != j

int lagrange(
	unsigned char n,   // number of points to interpolate
	unsigned char m,   // index of this point
	unsigned char *xi, // x coordinates of all points
	unsigned char x    // x coordinate to evaluate
) {
	int log_result = 0;
	unsigned char i;

	for(i=0;i<n;++i) {
		if(i!=m) {
			if(x == xi[i]) {
				return 0;
			}
			
			if(xi[m] == xi[i]) {
				return -1;
			}

			// compute logs of sums regardless
			log_result += gf256_log[x ^ xi[i]] - gf256_log[xi[m] ^ xi[i]];
			log_result = (255+log_result) % 255;
		}
	}

	return gf256_exp[log_result];
}



// Interpolate
// given a polynomial that goes through n points { (x_i, y_i) }
// calculate the value for y at a given x
//
// This is readily accomplished by computing the lagrange polynomials
// for [x] and using them to generate the appropriate interpolation
// to match [y].
//                 n
//                ---
// P([x],[y],x) = >   pn_i(x,[x]) * y_i 
//                ---
//                 i
//
// On success, this returns the length of the recovered secret. On failure,
// it returns -1.
int interpolate(
	unsigned char n,       // number of points to interpolate
	unsigned char* xi,     // x coordinates for points
	unsigned int yl,       // length of y coordinate array 
	unsigned char **yij,   // n arrays of yl bytes representing y values
	unsigned char x,       // x coordinate to interpolate
	unsigned char* result  // space for yl bytes of results
) {
	unsigned char lags[16];
  	unsigned char i;
  	unsigned int j;

	// Calculate lagrange polynomials for the target value.
	// the lagrange polynomial function will return -1 if there is a
	// duplicate in one of the x-coordinates.
  	for(i=0;i<n;++i) {
  		int l = lagrange(n,i,xi,x);
  		if(l==-1) {
  			return -1;
  		}
  		lags[i] = l;  
  	}

	for(j=0; j<yl; ++j) {
		result[j] = 0;
		for(i=0;i<n;++i) {
			if(lags[i] != 0 && yij[i][j] != 0) {
				result[j] ^= gf256_mult(lags[i], yij[i][j]);
				//result[j] ^= gf256_exp[ (gf256_log[lags[i]] + gf256_log[yij[i][j]]) % 255 ];
			}
		}
	}

	return yl;  	
}


//////////////////////////////////////////////////
// hmac sha256
//
#include <openssl/evp.h>
#include <openssl/hmac.h>

unsigned char* hmac_sha256(
	const void *key, 
	int keylen,
	const unsigned char *data, 
	int datalen,
    unsigned char *result, 
    unsigned int* resultlen)
{
    return HMAC(EVP_sha256(), key, keylen, data, datalen, result, resultlen);
}


unsigned char* create_digest(
	unsigned char *random_data, 
	unsigned int rdlen, 
	unsigned char *shared_secret, 
	unsigned int sslen,
	unsigned char *result) {

	unsigned char buf[32];
	unsigned int l = 32;
	hmac_sha256(random_data, rdlen, shared_secret, sslen, buf, &l);

	for(unsigned j=0; j<4; ++j) {
		result[j] = buf[j];
	}
	return result;
}

static unsigned char b = 0;

void randombytes(unsigned char *p, int len) {
	for(int i=0; i< len; ++i) {
		p[i] = b;
		b+= 17;
	}
}

//////////////////////////////////////////////////
// shamir sharing
int split_secret(
	unsigned char threshold,
	unsigned char share_count,
	unsigned char *secret,
	unsigned int secret_length,
	unsigned char *result
) {
	if( share_count > MAX_SHARE_COUNT || secret_length > MAX_SECRET_LENGTH) {
		return -1;
	}

	if(threshold == 1) {
		// just return share_count copies of the secret
		unsigned char *share = result;
		for(unsigned char i=0; i< share_count; ++i, share += secret_length) {
			for(unsigned char j=0; j<secret_length; ++j) {
				share[j] = secret[j];
			}
		}
		return share_count;
	} else {
		unsigned char digest[256];
		unsigned char x[16];
		unsigned char *y[16];
		unsigned char n =0;
		unsigned char *share = result;
				
		for(unsigned char i=0; i< threshold-2; ++i, share+=secret_length) {
			randombytes(share, secret_length);
			x[n] = i;
			y[n] = share;
			n+=1;	
		}

		// generate secret_length - 4 bytes worth of random data
		randombytes(digest+4, secret_length-4);
		// put 4 bytes of digest at the top of the digest array
		create_digest(digest+4, secret_length-4, secret, secret_length, digest);
		x[n] = DIGEST_INDEX;
		y[n] = digest;
		n+=1;
		
		x[n] = SECRET_INDEX;
		y[n] = secret;
		n+=1;

		for(unsigned char i=threshold -2; i<share_count; ++i, share += secret_length) {
			if( interpolate(n, x, secret_length, y, i, share) < 0) {
				return -1;
			}
		}		
	} 
	return share_count;
}


// returns the number of bytes written to the secret array, or -1 if there was an error
int recover_secret(
	unsigned char threshold,
	unsigned char *x,
	unsigned char **shares,
	unsigned int share_length,
	unsigned char *secret
) {
	unsigned char digest[MAX_SECRET_LENGTH];
	unsigned char verify[4];
	unsigned char valid = 1;

	if(threshold == 1) {
		for(unsigned char j=0; j<share_length; ++j) {
			secret[j] = shares[0][j];
		}
		return share_length;
	} 

	if( interpolate(threshold, x, share_length, shares, DIGEST_INDEX, digest) < 0 ||
		interpolate(threshold, x, share_length, shares, SECRET_INDEX, secret) < 0 
	) {
		return -1;
	}

	create_digest(digest+4, share_length-4, secret, share_length, verify);

	for(unsigned char i=0; i<4; i++) {
		valid &= digest[i] == verify[i];
	}

	if(!valid) {
		printf("Recover secret failed checksum.\n");
		return -1;
	}
	return share_length;	
}


//////////////////////////////////////////////////
// slip39 words
//
int lookup(char *word) {
	int hi=WORDLIST_SIZE;
	int lo=-1;

	while(hi>lo+1) {
		int mid = (hi + lo) / 2;
		int cmp = strcmp(word, wordlist[mid]);
		if(cmp > 0) {
            lo = mid;
		} else if(cmp < 0){
			hi = mid;
		} else {
			return mid;
		}
	}
	return -1;
}

int parse_words(
	char *words_string, 
	unsigned short *words, 
	unsigned int words_length
) {
	char buf[16];
	unsigned char i=0;
	unsigned int j=0;
	char *p = words_string;

	while(*p) {
		for(i=0; *p>='a' && *p<='z'; i++, p++) {
			if(i<15) {
				buf[i] = *p;
			} else {
				buf[15] = 0;
			}
		}
		if(i<15) {
			buf[i] = 0;
		}
			
		if(j<words_length) {
			int w = lookup(buf);
			if(w<0) {
				printf("%s is not valid.\n", buf);
				return -1;
			} else {
				words[j] = w;
			}
		}
		j++;

		while(*p && (*p<'a' || *p>'z')) {
			p++;
		}
	}
	return j;
}

// returns the number of words written or -1 if there was an error
int toWords(
	void *buffer,          // byte buffer to encode into 10-bit words
	size_t size,           // buffer size
	unsigned short *words, // destination for words
	size_t max             // maximum number of words to write
) {
	unsigned char * buf = buffer;
	unsigned int byte = 0;
	unsigned int word = 0;
	int bits = 0;
	unsigned int i = 0;

	if(max < bytes_to_words(size)) {
		printf("Not enough space to encode into 10-bit words \n");
		return -1;
	}
	
	while(byte < size && word < max) {
		while(bits < 10) {
			i =  i << 8;
			bits += 8;
			if(byte < size) {
				i = i | buf[byte++];
			} 
		}

		words[word++] = (i >> (bits-10));
		i = i & ((1<<(bits-10))-1);
		bits -= 10;
	}	

	if(bits > 0) {
		words[word++] = i << (10-bits);
	}

	return word;
}

// returns the number of bytes written, or -1 if there was an error
int fromWords(
	unsigned short *words, // words to decode
	size_t wordsize,       // number of words to decode
	void *buffer,          // space for result
	size_t size            // total space available
) {
	unsigned char * buf = buffer;
	unsigned int word = 0;
	int bits = 0;
	unsigned int byte = 0;
	unsigned int i = 0;

	if(size < words_to_bytes(wordsize)) {
		printf("Not enough space to decode %d 10-bit words into bytes. (%d bytes needed, %d bytes available)\n", (int) wordsize, (int) words_to_bytes(wordsize), (int)size);
		return -1;
	}	

	while(word < wordsize && byte < size) {
		i = (i << 10) | words[word++];
		bits += 10;

		while(bits >= 8 && byte < size) {
			buf[byte++] = (i >> (bits -8));
			i = i & ((1<<(bits-8))-1);
			bits -= 8;
		}
	}

	if(bits && byte<size && (byte&1) == 1 ) {
		buf[byte++] = i << (8-bits);
	}	

	return byte;
}

void test_gf256() {
	for(unsigned char i = 1; i !=0; ++i ) {
		int logi = gf256_log[i];
		if(gf256_exp[logi] != i) {printf("exp log failed %d",i);}
	}
}

void test_lagrange() {
	unsigned char xi[3];
	
	for(int i=0; i< 256; ++i) {
		xi[0] = i;
		for(int j=i+1; j<256; ++j) {
			xi[1] = j;
			for(int k=j+1; k<256; ++k) {
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
					exit(-1);							
				}
			}

			// For two parameter lagrange polynomials, test to see that 
			// zero one results do not result unless x in [xi]
			for(int l=0;l<256;++l) {
				if( l!=i && l!=j && 
					( lagrange(2,0,xi,l) == 0 ||
					  lagrange(2,1,xi,l) == 0 ||
					  lagrange(2,0,xi,l) == 1 ||
					  lagrange(2,1,xi,l) == 1
					)
				) {
					printf("lagrange failure 2 %d %d %d\n", i, j, l);
					exit(-1);							
				}
			}
		}
	}
}

void test_interpolation(void) {
	unsigned char x[] = { 0, 1 };
	unsigned char y0[] = { 1 };
	unsigned char y1[] = { 2 };
	unsigned char *y[] = {y0, y1};
	unsigned char tx[] = { 0, 0 };
	unsigned char res[] = {0};
	
	unsigned char yr[256];
	unsigned char *ty[] = { yr+0, yr+1 };

	// Interpolate the entire range of the polynomial
	for(unsigned char i=0; i<255; ++i) {
		interpolate(2,x,1,y,i,yr+i);
	}

	// pick any two points on the curge	
	for(unsigned char j = 0; j<100; ++j) {
		for(unsigned char k = j+1; k<101; ++k) {
			tx[0] = j;
			tx[1] = k;
			ty[0] = yr + j;
			ty[1] = yr + k;
			// make sure that interpolating a curve through those
			// tow points has the same x=0 value
			interpolate(2,tx,1,ty,0,res);
			if(res[0] != 1) {
				printf("interpolation failure %d %d %d\n",j,k,res[0]);
			}
		}
	}
}


typedef struct group_descriptor_struct {
	unsigned char threshold;
	unsigned char count;
} group_descriptor;


//////////////////////////////////////////////////
// encrypt/decrypt
//
// TODO: these are just pass thrus for now 


#include <openssl/evp.h>
#include <openssl/sha.h>
// crypto.h used for the version
#include <openssl/crypto.h>

unsigned int  _get_salt(
	unsigned short identifier, 
	unsigned char *result, 
	unsigned int result_length
) {
	if(result_length < 8) {
		return -1;
	}
	
	for(unsigned int i=0; i<6; ++i) {
		result[i] = customization[i];
	}
	result[6] = identifier >> 8;
	result[7] = identifier & 0xff;
	return 8;
}

void round_function(
	unsigned char i, 
	char *passphrase, 
	unsigned char exp, 
	unsigned char *salt,
	unsigned int salt_length, 
	unsigned char *r,
	unsigned int r_length,
	unsigned char *dest,
	unsigned int dest_length
) {
	unsigned int pass_length = strlen(passphrase) + 1; 
	char pass[pass_length+2];
	sprintf(pass+1, "%s", passphrase);
	pass[0] = i;
	unsigned int iterations = BASE_ITERATION_COUNT << exp;
	unsigned char saltr[salt_length + r_length];
	memcpy(saltr, salt, salt_length);
	memcpy(saltr+salt_length, r, r_length);		

    PKCS5_PBKDF2_HMAC(pass, pass_length, 
    	saltr, salt_length+r_length, 
    	iterations, 
    	EVP_sha256(), 
    	dest_length, dest);
}	

void test_round_function() {
	// data from this test was taken from running the round function
	// on pass one of encrypting the string "abcd" with the empty
	// password, and a group identifier of 1234
	unsigned char salt[] = { 's', 'h', 'a', 'm', 'i', 'r', 4, 210 };
	unsigned char r[] = { 'c', 'd' };
	unsigned char d[2];
	
	round_function(0,"",0,salt,8,r,2,d,2);

	if(d[0] == 183 && d[1] == 32) {
		printf("pass\n");
	} else {
		printf("fail\n");
	}

	round_function(0,"TREZOR",0,salt,8,r,2,d,2);
	if(d[0] == 156 && d[1] == 169) {
		printf("pass\n");
	} else {
		printf("fail\n");
	}

}

void encrypt(
	unsigned char *input,
	unsigned int input_length,
	char *passphrase,
	unsigned int iteration_exponent,
	unsigned short identifier, 
	unsigned char *output) {

	unsigned int half_length = input_length / 2;
	unsigned char *l, *r, *t, f[half_length];
	unsigned char salt[8];

	memcpy(output, input+half_length, half_length);
	memcpy(output + half_length, input, half_length);
	r = output;
	l = output+half_length;
	
	_get_salt(identifier, salt, 8);

	for(unsigned char i=0; i<ROUND_COUNT; ++i) {
		round_function(i, passphrase, iteration_exponent, salt, 8, r, half_length, f, half_length);
		t = l;
		l = r;
		r = t;
		for(unsigned int j=0;j<half_length;++j) {
			r[j] = r[j] ^ f[j];
		}
	}

}

void test_encrypt_function() {
	// Data for this test was generated by running the equivalent 
	// _encrypt() function in the python reference code
	char *input = "abcd";
	unsigned char output[4];

	encrypt((unsigned char *)input, 4, "", 0, 1234, output);

	if( output[0] == 167 && output[1] == 251 && output[2]==61 && output[3] == 147) {
		printf("pass\n");
	} else 	{
		printf("fail\n");
	}


	encrypt((unsigned char *)input, 4, "TREZOR", 0, 1234, output);
	if( output[0] == 41 && output[1] == 155 && output[2]==1 && output[3] == 50) {
		printf("pass\n");
	} else 	{
		printf("fail\n");
	}
}

void decrypt(
	unsigned char *input,
	unsigned int input_length,
	char *passphrase,
	unsigned int iteration_exponent,
	unsigned short identifier, 
	unsigned char *output) {

	unsigned int half_length = input_length / 2;
	unsigned char *l, *r, *t, f[half_length];
	unsigned char salt[8];

	memcpy(output, input+half_length, half_length);
	memcpy(output + half_length, input, half_length);

	r = output;
	l = output+half_length;
		
	_get_salt(identifier, salt, 8);

	for(unsigned char i=0; i<ROUND_COUNT; ++i) {	
		round_function(ROUND_COUNT-1-i, passphrase, iteration_exponent, salt, 8, r, half_length, f, half_length);
		t = l;
		l = r;
		r = t;
		for(unsigned int j=0;j<half_length;++j) {
			r[j] = r[j] ^ f[j];
		}
	}
}

//////////////////////////////////////////////////
// encode mnemonic
unsigned int encode_mnemonic(
    unsigned short identifier, 
    unsigned char iteration_exponent, 
    unsigned char group_index, 
    unsigned char group_threshold, 
    unsigned char group_count,
    unsigned char member_index,
    unsigned char member_threshold,
    unsigned char *value,
    unsigned int value_length,
    unsigned short *destination,
    unsigned int destination_length) {

	// pack the id, exp, group and member data into 4 10-bit words:
    // [id:1  5][exp:5][g_index:4][g_thresh*:4][g_count*:4][m_idx:4][m_thrsh*:4]    	
    // [w0:10][  w1:10][w2:10                      ][w3:10                     ]

	// change offset and clip group and member coordinate data
	unsigned short gt = (group_threshold -1) & 15;
	unsigned short gc = (group_count -1) & 15;
	unsigned short mi = (member_index) & 15;
	unsigned short mt = (member_threshold -1) & 15;

 	destination[0] = (identifier >> 5) & 1023;
 	destination[1] = ((identifier << 5) | iteration_exponent) & 1023;
 	destination[2] = ((group_index << 6) | (gt << 2) | (gc >> 2)) & 1023;
    destination[3] = ((gc << 8) | (mi << 4) | (mt)) & 1023;

    unsigned int words = toWords(value, value_length, destination+4, destination_length - METADATA_LENGTH_WORDS);
	rs1024_create_checksum(destination, words + METADATA_LENGTH_WORDS);	

	return words+METADATA_LENGTH_WORDS;
 }





//////////////////////////////////////////////////
// decode mnemonic
unsigned int decode_mnemonic(
	unsigned short *mnemonic,
	unsigned int mnemonic_length,
	unsigned short *identifier,
	unsigned char *iteration_exponent,
	unsigned char *group_index,
	unsigned char *group_threshold,
	unsigned char *group_count,
	unsigned char *member_index,
	unsigned char *member_threshold,
	unsigned char *value,
	unsigned int value_length
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
	
	*identifier = mnemonic[0] << 5 | mnemonic[1] >> 5;
	*iteration_exponent = mnemonic[1] & 31;
	*group_index = mnemonic[2] >> 6;
	*group_threshold = gt;
	*group_count = gc; 
	*member_index = (mnemonic[3]>>4) & 15;
	*member_threshold = (mnemonic[3]&15) + 1;

	return fromWords(mnemonic+4, mnemonic_length - 7, value, value_length);
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


void print_mnemonic(unsigned short *mnemonic, unsigned int mnemonic_length) {
	unsigned char value[256];

	unsigned short id;
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
	unsigned short *mnemonics,
	unsigned int buffer_size
) {
	unsigned short identifier = 0;
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

	for(unsigned char *p = passphrase; *p; p++) {
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

	unsigned short *mnemonic = mnemonics;
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
	unsigned short **mnemonics,   // array of pointers to 10-bit words
	unsigned int mnemonics_words, // number of words in each share
	unsigned int mnemonics_shares,// total number of shares
	char *passphrase,             // passphrase to unlock master secret
	unsigned char *buffer,        // working space, and place to return secret
	int buffer_length             // total amount of working space
) {
	unsigned short identifier;
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
		unsigned short id;
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

void test_split_recover(void) {
	char *test = "The quick brown fox jumped over the lazy dog.";

	unsigned char shares[512];
	unsigned char secret[50];
		
	//unsigned short words1[45];
	//unsigned char result[60];
	//int wc = 0;
	//int len = 0;

	int secret_length = strlen(test)+1;

	int share_count = split_secret(3, 10, (unsigned char *)test, secret_length, shares);

	printf("share count %d\n", share_count);
	unsigned char *sh[10];
	for(unsigned char i=0;i<10;++i) {
		sh[i] = shares + i*secret_length;
	}

	for(unsigned char i=0;i<8;++i) {
		for(unsigned char j=i+1;j<9;++j) {
			for(unsigned char k=j+1; k<10;++k) {
				unsigned char x[] = {j, i, k};
				unsigned char *y[] = {sh[j], sh[i], sh[k]};				

				int recovery = recover_secret(3, x, y, secret_length, secret);
				printf("%d  %s\n", recovery, (char *) secret);

			}
		}
	}
	//unsigned char x[] = {0,1,2};
	//unsigned char *y[] = {shares, shares+secret_length, shares+2*secret_length};

	//int recovery = recover_secret(3, x, y, secret_length, secret);
	//printf("%d  %s\n", recovery, (char *) secret);

	//wc = toWords(test, strlen(test)+1, words1, 40);

	//rs1024_create_checksum(words1, wc+3);	
	//int good = rs1024_verify_checksum(words1, wc+3);
	
	//len = fromWords(words1, wc, result, 50);

	//printf("%d\n",len);
	
	//for(i =0; i< wc+3; ++i) {
	//	printf("%s ", wordlist[words1[i]]);
	//}

	//printf("\n");
	//printf("good: %d\n", good);
	//printf("%s\n", result);
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

	unsigned short mnemonics[1024];
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


	unsigned short* recovery_mnemonics[] = {
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

	unsigned short mnemonics[1024];
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

	unsigned short* recovery_mnemonics[] = {
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
	
    unsigned short words[20];
    unsigned char result[1024];
	
    int n = parse_words(word_string, words, 20);
	   
    if(n<0 || n>20) {
    	printf("invalid result from parse_words: %d\n", n);
    }

	for(int i=0; i<n; ++i) {
		printf("%s ", wordlist[ words[i]]);
	}
	printf("\n");
	
	unsigned short* recovery_mnemonics[] = {
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
	unsigned short recovery[100];
	unsigned int n;
	unsigned char result[1024];
	
	for(int i=0;i<5;++i) {
		n = parse_words(shares[i],recovery + i * 20,20);
	}

	unsigned short *rc[] = {recovery,recovery+20,recovery+40,recovery+60,recovery+80};
	
	int m = combine_mnemonics(rc, n, 5, "TREZOR", result, 1024);
	if(m>0) {
		print_hex(result,m);	
	}
}


int main(int argc, char *argv[]) {

    precompute_gf256_exp_log_tables();

	//test_gf256();
	//test_lagrange();
	//test_interpolation();

	//test_split_recover();

	test_generate_combine1();

	//test_encrypt_decrypt();
	//test_valid_mnemonic();
	//test_round_function();
	//test_encrypt_function();
	//test_multi();
}