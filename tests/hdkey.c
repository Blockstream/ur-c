
#include "unity.h"
#include "unity_fixture.h"

#include "urc/urc.h"

#include "helpers.h"
#include "internals.h"

#define BUFLEN 1024

TEST_GROUP(hdkey);

TEST_SETUP(hdkey) {}
TEST_TEAR_DOWN(hdkey) {}

TEST(hdkey, test_vector_1)
{
    // https://github.com/BlockchainCommons/Research/blob/master/papers/urc-2020-007-hdkey.md#exampletest-vector-1
    const char *hex = "a301f503582100e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35045820873dff81c02f525623fd1f"
                      "e5167eac3a55a049de3d314bb42ee227ffed37d508";
    const char *expected =
        "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";

    uint8_t raw[BUFLEN];
    size_t len = h2b(hex, BUFLEN, (uint8_t *)(&raw));
    TEST_ASSERT_GREATER_THAN_INT(0, len);

    crypto_hdkey hdkey;
    int err = urc_crypto_hdkey_deserialize(raw, len, &hdkey);
    TEST_ASSERT_EQUAL(URC_OK, err);
    TEST_ASSERT_EQUAL(hdkey_type_master, hdkey.type);

    char *out;
    err = urc_crypto_hdkey_format(&hdkey, &out);
    TEST_ASSERT_EQUAL(URC_OK, err);
    TEST_ASSERT_EQUAL_STRING(expected, out);
    urc_string_free(out);

    {
        const char *expected = "[00000000]";
        const size_t expected_len = strlen(expected);
        TEST_ASSERT_GREATER_THAN(expected_len, BUFLEN);
        char *keyorigin = malloc(BUFLEN);
        TEST_ASSERT_NOT_NULL(keyorigin);
        keyorigin[0] = '\0';

        int result = format_keyorigin(&hdkey, keyorigin, BUFLEN);
        TEST_ASSERT_GREATER_THAN(0, result);
        TEST_ASSERT_EQUAL_STRING(expected, keyorigin);
        free(keyorigin);
    }
    {
        const char *expected = "";
        const size_t expected_len = strlen(expected);
        TEST_ASSERT_GREATER_THAN(expected_len, BUFLEN);
        char *derivationpath = malloc(BUFLEN);
        TEST_ASSERT_NOT_NULL(derivationpath);
        derivationpath[0] = '\0';

        int result = format_keyderivationpath(&hdkey, derivationpath, BUFLEN);
        TEST_ASSERT_EQUAL(0, result);
        TEST_ASSERT_EQUAL_STRING(expected, derivationpath);
        free(derivationpath);
    }
}

TEST(hdkey, test_vector_2)
{
    // https://github.com/BlockchainCommons/Research/blob/master/papers/urc-2020-007-hdkey.md#exampletest-vector-2
    const char *hex = "a5035821026fe2355745bb2db3630bbc80ef5d58951c963c841f54170ba6e5c12be7fc12a6045820ced155c72456255881793514ed"
                      "c5bd9447e7f74abb88c6d6b6480fd016ee8c8505d90131a1020106d90130a1018a182cf501f501f500f401f4081ae9181cf3";
    const char *expected =
        "tpubDHW3GtnVrTatx38EcygoSf9UhUd9Dx1rht7FAL8unrMo8r2NWhJuYNqDFS7cZFVbDaxJkV94MLZAr86XFPsAPYcoHWJ7sWYsrmHDw5sKQ2K";

    uint8_t raw[BUFLEN];
    size_t len = h2b(hex, BUFLEN, (uint8_t *)(&raw));
    TEST_ASSERT_GREATER_THAN_INT(0, len);

    crypto_hdkey hdkey;
    int err = urc_crypto_hdkey_deserialize(raw, len, &hdkey);
    TEST_ASSERT_EQUAL(URC_OK, err);
    TEST_ASSERT_EQUAL(hdkey_type_derived, hdkey.type);

    char *out;
    err = urc_crypto_hdkey_format(&hdkey, &out);
    TEST_ASSERT_EQUAL(URC_OK, err);
    TEST_ASSERT_EQUAL_STRING(expected, out);
    urc_string_free(out);

    {
        const char *expected = "[e9181cf3/44'/1'/1'/0/1]";
        const size_t expected_len = strlen(expected);
        TEST_ASSERT_GREATER_THAN(expected_len, BUFLEN);
        char *keyorigin = malloc(BUFLEN);
        TEST_ASSERT_NOT_NULL(keyorigin);
        keyorigin[0] = '\0';
        int result = format_keyorigin(&hdkey, keyorigin, BUFLEN);
        TEST_ASSERT_GREATER_THAN(0, result);
        TEST_ASSERT_EQUAL_STRING(expected, keyorigin);
        free(keyorigin);
    }
    {
        const char *expected = "";
        const size_t expected_len = strlen(expected);
        TEST_ASSERT_GREATER_THAN(expected_len, BUFLEN);
        char *derivationpath = malloc(BUFLEN);
        TEST_ASSERT_NOT_NULL(derivationpath);
        derivationpath[0] = '\0';

        int result = format_keyderivationpath(&hdkey, derivationpath, BUFLEN);
        TEST_ASSERT_EQUAL(0, result);
        TEST_ASSERT_EQUAL_STRING(expected, derivationpath);
        free(derivationpath);
    }
}
