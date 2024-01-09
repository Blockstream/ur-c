
#include "unity_fixture.h"

#include "urc/urc.h"

#include "helpers.h"

#define BUFLEN 1000

TEST_GROUP(output);

TEST_SETUP(output) {}
TEST_TEAR_DOWN(output) {}

TEST(output, test_vector_1)
{
    // https://github.com/BlockchainCommons/Research/blob/master/papers/urc-2020-010-output-desc.md#exampletest-vector-1
    const char *hex = "d90193d90132a103582102c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";
    const char *expected = "pkh(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)";

    uint8_t raw[BUFLEN];
    size_t len = h2b(hex, BUFLEN, (uint8_t *)(&raw));
    TEST_ASSERT_GREATER_THAN_INT(0, len);

    crypto_output output;
    int err = urc_crypto_output_deserialize(raw, len, &output);
    TEST_ASSERT_EQUAL(URC_OK, err);
    TEST_ASSERT_EQUAL(output_type__, output.type);

    char *out;
    err = urc_crypto_output_format(&output, urc_crypto_output_format_mode_default, &out);
    TEST_ASSERT_EQUAL(URC_OK, err);
    TEST_ASSERT_EQUAL_STRING(expected, out);
    urc_string_free(out);
}

TEST(output, test_vector_2)
{
    // https://github.com/BlockchainCommons/Research/blob/master/papers/urc-2020-010-output-desc.md#exampletest-vector-2
    const char *hex = "d90190d90194d90132a103582103fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556";
    const char *expected = "sh(wpkh(03fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556))";

    uint8_t raw[BUFLEN];
    size_t len = h2b(hex, BUFLEN, (uint8_t *)(&raw));
    TEST_ASSERT_GREATER_THAN_INT(0, len);

    crypto_output output;
    int err = urc_crypto_output_deserialize(raw, len, &output);
    TEST_ASSERT_EQUAL(URC_OK, err);
    TEST_ASSERT_EQUAL(output_type_sh, output.type);

    char *out;
    err = urc_crypto_output_format(&output, urc_crypto_output_format_mode_default, &out);
    TEST_ASSERT_EQUAL(URC_OK, err);
    TEST_ASSERT_EQUAL_STRING(expected, out);
    urc_string_free(out);
}

TEST(output, test_vector_4)
{
    // https://github.com/BlockchainCommons/Research/blob/master/papers/urc-2020-010-output-desc.md#exampletest-vector-4
    const char *hex =
        "d90193d9012fa503582102d2b36900396c9282fa14628566582f206a5dd0bcc8d5e892611806cafb0301f0045820637807030d55d01f9a0cb3a78395"
        "15d796bd07706386a6eddf06cc29a65a0e2906d90130a30186182cf500f500f5021ad34db33f030407d90130a1018401f480f4081a78412e3a";
    const char *expected =
        "pkh([d34db33f/44'/0'/"
        "0']xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL/1/*)";

    uint8_t raw[BUFLEN];
    size_t len = h2b(hex, BUFLEN, (uint8_t *)(&raw));
    TEST_ASSERT_GREATER_THAN_INT(0, len);

    crypto_output output;
    int err = urc_crypto_output_deserialize(raw, len, &output);
    TEST_ASSERT_EQUAL(URC_OK, err);
    TEST_ASSERT_EQUAL(output_type__, output.type);

    char *out;
    err = urc_crypto_output_format(&output, urc_crypto_output_format_mode_default, &out);
    TEST_ASSERT_EQUAL(URC_OK, err);
    TEST_ASSERT_EQUAL_STRING(expected, out);
    urc_string_free(out);
}
