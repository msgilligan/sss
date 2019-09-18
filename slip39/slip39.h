#ifndef SLIP39_H
#define SLIP39_H

#define RADIX_BITS 10
#define RADIX (1<<RADIX_BITS)
#define ID_LENGTH_BITS 15
#define ITERATION_EXP_LENGTH_BITS 5
#define ID_EXP_LENGTH_WORDS 2

#define bytes_to_words(n)  ( ( (n) * 8 + RADIX_BITS-1) / RADIX_BITS)
#define words_to_bytes(n)  ( ( (n) * RADIX_BITS ) / 8)

#define MAX_SHARD_COUNT 16
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

#define SECRET_SIZE 32

#define ERROR_NOT_ENOUGH_MNEMONIC_WORDS        -1
#define ERROR_INVALID_MNEMONIC_CHECKSUM        -2
#define ERROR_INVALID_MNEMONIC_GROUP_THRESHOLD -3
#define ERROR_SECRET_TOO_SHORT                 -4
#define ERROR_SECRET_TOO_LONG                  -5
#define ERROR_INVALID_GROUP_THRESHOLD          -6
#define ERROR_INVALID_SINGLETON_MEMBER         -7
#define ERROR_INSUFFICIENT_SPACE               -8
#define ERROR_INVALID_SECRET_LENGTH            -9
#define ERROR_INVALID_PASSPHRASE              -10
#define ERROR_INVALID_SHARD_SET               -11
#define ERROR_EMPTY_MNEMONIC_SET              -12
#define ERROR_DUPLICATE_MEMBER_INDEX          -13
#define ERROR_NOT_ENOUGH_MEMBER_SHARDS        -14
#define ERROR_INVALID_MEMBER_THRESHOLD        -15
#define ERROR_TOO_MANY_SHARDS                 -16
#define ERROR_INTERPOLATION_FAILURE           -17
#define ERROR_CHECKSUM_FAILURE                -18
#define ERROR_INVALID_PADDING                 -19
#define ERROR_NOT_ENOUGH_GROUPS               -20
#define ERROR_INVALID_SHARD_BUFFER            -21

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>


typedef struct group_descriptor_struct {
	uint8_t threshold;
	uint8_t count;
	const char **passwords;
} group_descriptor;

typedef struct slip39_shard_struct {
    uint16_t identifier;
    uint8_t iteration_exponent;
    uint8_t group_index;
    uint8_t group_threshold;
    uint8_t group_count;
    uint8_t member_index;
    uint8_t member_threshold;
    uint8_t value_length;
    uint8_t value[32];
} slip39_shard;

typedef struct group_struct {
	uint8_t group_index;
	uint8_t member_threshold;
	uint8_t count;
	uint8_t member_index[16];
	const uint8_t *value[16];
} slip39_group;

uint32_t rs1024_polymod(
	const uint16_t *values,    // values - 10 bit words
	uint32_t values_length // number of entries in the values array
);

void rs1024_create_checksum(
	uint16_t *values, // data words (10 bit)
	uint32_t n          // length of the data array, including three checksum word
);

uint8_t rs1024_verify_checksum(
	const uint16_t *values,  // data words
	uint32_t n         // length of the data array
);


// returns the 10-bit integer that a string represents, or -1
// if the string is not a code word.
int16_t lookup(const char *word);

const char *slip39_word(int16_t word);

// converts a string of whitespace delimited mnemonic words
// to an array of 10-bit integers. Returns the number of integers
// written to the buffer.
uint32_t parse_words(
    const char *words_string,
    uint16_t *words,
    uint32_t words_length
);

// convert a buffer of bytes into 10-bit mnemonic words
// returns the number of words written or -1 if there was an error
int32_t toWords(
    const uint8_t *buffer, // byte buffer to encode into 10-bit words
    uint32_t size,   // buffer size
    uint16_t *words, // destination for words
    uint32_t max     // maximum number of words to write
);

// convert a buffer of words into bytes
// returns the number of bytes written or -1 if there was an error
int32_t fromWords(
    const uint16_t *words, // words to decode
    uint32_t wordsize,       // number of words to decode
    uint8_t *buffer,          // space for result
    size_t size            // total space available
);


// fills the destination buffer with count random bytes
void randombytes(uint8_t *dest, uint32_t count);

// creates an hmac from the data, storing it in the result field
// the nnumber of pytes written is stored in the resultlen pointer
// returns a pointer to the result buffer
uint8_t * hmac_sha256(
	const uint8_t *key,
	uint32_t keylen,
	const uint8_t *data,
	uint32_t datalen,
    uint8_t *result,
    unsigned int *resultlen);

// TODO: explain
uint8_t* create_digest(
	const uint8_t *random_data,
	uint32_t rdlen,
	const uint8_t *shared_secret,
	uint32_t sslen,
	uint8_t *result
);

//////////////////////////////////////////////////
// slip39 shamir sharing

// TODO: explain
int32_t split_secret(
	uint8_t threshold,
	uint8_t shard_count,
	const uint8_t *secret,
	uint32_t secret_length,
	uint8_t *result
);

// TODO: explain
// returns the number of bytes written to the secret array, or -1 if there was an error
int32_t recover_secret(
	uint8_t threshold,
	const uint8_t *x,
	const uint8_t **shards,
	uint32_t shard_length,
	uint8_t *secret
);

// TODO: explain
void round_function(
	uint8_t i,
	const char *passphrase,
	uint8_t exp,
	const uint8_t *salt,
	uint32_t salt_length,
	const uint8_t *r,
	uint32_t r_length,
	uint8_t *dest,
	uint32_t dest_length
);

// TODO: explain
void slip39_encrypt(
	const uint8_t *input,
	uint32_t input_length,
	const char *passphrase,
	uint8_t iteration_exponent,
	uint16_t identifier,
	uint8_t *output
);

// TODO: EXPLAIN
void slip39_decrypt(
	const uint8_t *input,
	uint32_t input_length,
	const char *passphrase,
	uint8_t iteration_exponent,
	uint16_t identifier,
	uint8_t *output
);

//////////////////////////////////////////////////
// encode mnemonic
unsigned int encode_mnemonic(
    const slip39_shard *shard,
    uint16_t *destination,
    uint32_t destination_length
);

//////////////////////////////////////////////////
// decode mnemonic
unsigned int decode_mnemonic(
	const uint16_t *mnemonic,
	uint32_t mnemonic_length,
	slip39_shard *shard
);

void print_hex(
    const uint8_t *buffer,
    uint32_t length
);

void print_mnemonic(
    const uint16_t *mnemonic,
    unsigned int mnemonic_length
);

void print_group(slip39_group *g, unsigned int secret_length);

/**
 * generate a set of shards that can be used to reconstuct a secret
 * using the given group policy
 *
 * returns: the number of shards generated if successful,
 *          or a negative number indicating an error code when unsuccessful
 *
 * inputs: group_threshold: the number of groups that need to be satisfied in order
 *                          to reconstruct the secret
 *         groups: an array of group descriptors
 *         groups_length: the length of the groups array
 *         master_secret: pointer to the secret to split up
 *         master_secret_length: length of the master secret in bytes.
 *                               must be >= 16, <= 32, and even.
 *         passphrase: string to use to encrypt the master secret
 *         iteration_exponent: exponent to use when calculating the number of rounds of encryption
 *                             to go through when encrypting the master secret.
 *         shards: array of shard structures to store the result ing
 *         shards_size: length of the shards array
 */

int generate_shards(
    uint8_t group_threshold,
    const group_descriptor *groups,
    uint8_t groups_length,
    const uint8_t *master_secret,
    uint32_t master_secret_length,
    const char *passphrase,
    uint8_t iteration_exponent,
    slip39_shard *shards,
    uint16_t shards_size
);

/**
 * combine a set of shards to reconstuct a secret
 *
 * returns: the length of the reconstructed secret if successful
 *          or a negative number indicating an error code when unsuccessful
 *
 * inputs: shards: an array of shards to combine
 *         shards_count: length of the shards array
 *         passphrase: passphrase to use encrypt the resulting secret
 *         passwords: array of strings to use to decrypt shard data
 *                    passing NULL disables password decrypt for all shards
 *                    passing NULL for the ith password will disable decrypt for the ith shard
 *                    passing a pointer to a string for the ith shard will cause the ith shard
 *                    to be decrypted with the string before recombination
 *         buffer: location to store the result
 *         buffer_length: maximum space available in buffer
 */

int combine_shards(
    const slip39_shard *shards, // array of shard structures
    uint16_t shards_count,      // number of shards in array
    const char *passphrase,     // passphrase to unlock master secret
    const char **passwords,     // passwords for the shards
    uint8_t *buffer,            // working space, and place to return secret
    uint32_t buffer_length      // total amount of working space
);


//////////////////////////////////////////////////
// generate mnemonics
int generate_mnemonics(
	uint8_t group_threshold,
	const group_descriptor *groups,
	uint8_t groups_length,
	const uint8_t *master_secret,
	uint32_t master_secret_length,
	const char *passphrase,
	uint8_t iteration_exponent,
	uint32_t *mnemonic_length,
	uint16_t *mnemonics,
	uint32_t buffer_size
);


/////////////////////////////////////////////////
// combine_mnemonics
int combine_mnemonics(
	const uint16_t **mnemonics, // array of pointers to 10-bit words
	uint32_t mnemonics_words,   // number of words in each shard
	uint32_t mnemonics_shards,  // total number of shards
	const char *passphrase,     // passphrase to unlock master secret
	const char **passwords,     // passwords protecting shards
	uint8_t *buffer,            // working space, and place to return secret
	uint32_t buffer_length      // total amount of working space
);


void encrypt_shard(
    slip39_shard *shard,
    const char *passphrase
);

void decrypt_shard(
    slip39_shard *shard,
    const char *passphrase
);

/////////////////////////////////////////////////
// Binary Buffer Representations

/**
 * decode a slip39 shard encoded in a binary buffer
 *
 * returns: if nothing went wrong, the number of bytes read from the buffer
 *          if an error ocurred, a negative number indicating one of the following
 *          error conditions:
 *            ERROR_INVALID_SHARD_BUFFER
 *            ERROR_SECRET_TOO_SHORT
 *            ERROR_SECRET_TOO_LONG
 *
 * inputs: shard: a pointer so a slip39_shard which will be populated upon success.
 *         buffer: a byte buffer containing a binary encoded shard
 *         buffer_length: the length of the buffer
 */

int decodeBinaryShare(
    slip39_shard *shard,
    const uint8_t *buffer,
    uint8_t buffer_length
);

/**
 * encode a slip39 shard into a binary buffer
 *
 * returns: if nothing went wrong, the number of bytes read from the buffer
 *          if an error ocurred, a negative number indicating one of the following
 *          error conditions:
 *            ERROR_INVALID_SHARD_BUFFER
 *
 * inputs: shard: a pointer so a slip39_shard which will be populated upon success.
 *         buffer: a byte buffer containing a binary encoded shard
 *         buffer_length: the length of the buffer
 */

int encodeBinaryShare(
    uint8_t *buffer,
    uint32_t buffer_length,
    const slip39_shard *shard
);

#endif