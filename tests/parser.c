#include "parser.h"
#include "bcr/bcr.h"
#include "unity.h"
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "helpers.h"

#define BUFSIZE 100

void setUp() {}
void tearDown() {}

void test_crypto_seed_parse() {
    // https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2020-006-urtypes.md#exampletest-vector-1
    const char *hex = "a20150c7098580125e2ab0981253468b2dbc5202d8641947da";
    uint8_t buffer[BUFSIZE];
    int len = h2b(hex, (uint8_t *)(&buffer), BUFSIZE);
    TEST_ASSERT_GREATER_THAN_INT(0, len);

    crypto_seed seed;
    bcr_error err = parse_seed(buffer, len, &seed);
    TEST_ASSERT_EQUAL(bcr_error_tag_noerror, err.tag);
    TEST_ASSERT_EQUAL(18394, seed.creation_date);
    TEST_ASSERT_EQUAL(199, seed.seed[0]);
    TEST_ASSERT_EQUAL(82, seed.seed[CRYPTO_SEED_SIZE-1]);
}

int main() {
    UNITY_BEGIN();
    RUN_TEST(test_crypto_seed_parse);
    return UNITY_END();
}
