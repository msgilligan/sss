#include "slip39.h"
#include <stdio.h>

slip39_shard shard1 = {
    1234, // identifier
    5,    // iteration exponent
    0,    // group index
    2,    // group threshold
    4,    // group count
    3,    // member index
    5,    // member threshold
    32,   // value_length
    { // value
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
        0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f
    }
};

slip39_shard shard2= {
    4321, // identifier
    3,    // iteration exponent
    1,    // group index
    2,    // group threshold
    5,    // group count
    6,    // member index
    7,    // member threshold
    16,   // value_length
    { // value
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    }
};

int shards_equal(slip39_shard *a, slip39_shard *b);

int shards_equal(slip39_shard *a, slip39_shard *b) {
    if( a->identifier != b->identifier ||
        a->iteration_exponent != b->iteration_exponent ||
        a->group_index != b->group_index ||
        a->group_threshold != b->group_threshold ||
        a->group_count != b->group_count ||
        a->member_index != b->member_index ||
        a->member_threshold != b->member_threshold ||
        a->value_length != b->value_length ) {
            return 0;
        }
    for(int i=0; i<a->value_length; ++i) {
        if(a->value[i] != b->value[i]) {
            return 0;
        }
    }

    return 1;
}

int test_encode_decode_buffer() {
    uint8_t buffer[50];
    slip39_shard decode;
    int result;

    // test encoding and decoding a 32 byte secret shard
    result = encode_binary_shard(buffer, 50, &shard1);
    if(result != 44) {
        // fail
        printf("shard1 encoding gave unexpected length\n");
        return 1;
    }


    result = decode_binary_shard(&decode, buffer, 50);
    if(result != 44) {
        printf("shard1 decoding gave unexpected length\n");
        return 1;
    }

    if( !shards_equal(&shard1, &decode)) {
        printf("shard1 decode not equal to original\n");
        return 1;
    }

    // test encoding and decoding a 16 byte secret shard
    result = encode_binary_shard(buffer, 50, &shard2);
    if(result != 28) {
        printf("shard2 encoding gave unexpected length\n");
        return 1;
    }

    result = decode_binary_shard(&decode, buffer, 50);
    if(result != 28) {
        printf("shard2 decoding gave unexpected length\n");
        return 1;
    }

    if( !shards_equal(&shard2, &decode)) {
        printf("shard2 decode not equal to original\n");
        return 1;
    }

    return 0;
}


int main(void) {
    uint8_t fail = 0;
    uint8_t t;


    t = test_encode_decode_buffer();
    fail = fail || t;
    printf("test encode decode buffer: %s\n", t ? "fail" : "pass" );

    //t = test_bad_buffer();
    //fail = fail || t;
    //printf("test bad buffer: %s\n", t ? "fail" : "pass" );

    return fail;
}
