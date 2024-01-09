
#include <string.h>

#include "unity_fixture.h"

#include "urc/core.h"
#include "urc/crypto_eckey.h"

#include "helpers.h"

#define BUFLEN 1024

TEST_GROUP(eckey);

TEST_SETUP(eckey) {}
TEST_TEAR_DOWN(eckey) {}

TEST(eckey, test_vector_1) {
    //https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2020-008-eckey.md#exampletest-vector-1
    const char *hex = "a202f50358208c05c4b4f3e88840a4f4b5f155cfd69473ea169f3d0431b7a6787a23777f08aa";
    const char *expected = "8c05c4b4f3e88840a4f4b5f155cfd69473ea169f3d0431b7a6787a23777f08aa";
    
    uint8_t raw[BUFLEN];
    size_t len = h2b(hex, BUFLEN, (uint8_t *)&raw);
    TEST_ASSERT_GREATER_THAN_INT(0, len);

    crypto_eckey eckey;
    int result = urc_crypto_eckey_deserialize(raw, len, &eckey);
    TEST_ASSERT_EQUAL(URC_OK, result);
    TEST_ASSERT_EQUAL(eckey_type_private, eckey.type);

    char *output;
    result = urc_crypto_eckey_format(&eckey, &output);
    TEST_ASSERT_EQUAL(URC_OK, result);
    TEST_ASSERT_EQUAL_STRING(expected, output);

    urc_string_free(output);
}

TEST(eckey, test_vector_2) {
    //https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2020-008-eckey.md#exampletest-vector-2
    const char *hex = "a103582103bec5163df25d8703150c3a1804eac7d615bb212b7cc9d7ff937aa8bd1c494b7f";
    const char *expected = "03bec5163df25d8703150c3a1804eac7d615bb212b7cc9d7ff937aa8bd1c494b7f";
    
    uint8_t raw[BUFLEN];
    size_t len = h2b(hex, BUFLEN, (uint8_t *)&raw);
    TEST_ASSERT_GREATER_THAN_INT(0, len);

    crypto_eckey eckey;
    int err = urc_crypto_eckey_deserialize(raw, len, &eckey);
    TEST_ASSERT_EQUAL(URC_OK, err);
    TEST_ASSERT_EQUAL(eckey_type_public_compressed, eckey.type);

    char *output;
    int result = urc_crypto_eckey_format(&eckey, &output);
    TEST_ASSERT_EQUAL(URC_OK, result);
    TEST_ASSERT_EQUAL_STRING(expected, output);

    urc_string_free(output);
}
