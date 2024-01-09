#include <string.h>

#include "unity_fixture.h"

#include "urc/urc.h"

#include "helpers.h"

#define BUFLEN 1000

TEST_GROUP(parser);

TEST_SETUP(parser) {}
TEST_TEAR_DOWN(parser) {}

TEST(parser, crypto_seed_deserialize)
{
    // https://github.com/BlockchainCommons/Research/blob/master/papers/urc-2020-006-urtypes.md#exampletest-vector-1
    const char *hex = "a20150c7098580125e2ab0981253468b2dbc5202d8641947da";
    uint8_t raw[BUFLEN];
    size_t len = h2b(hex, BUFLEN, (uint8_t *)&raw);
    TEST_ASSERT_GREATER_THAN_INT(0, len);

    crypto_seed seed;
    int err = urc_crypto_seed_deserialize(raw, len, &seed);
    TEST_ASSERT_EQUAL(URC_OK, err);
    TEST_ASSERT_EQUAL(18394, seed.creation_date);
    TEST_ASSERT_EQUAL_HEX(0xc7, seed.seed[0]);
    TEST_ASSERT_EQUAL_HEX(0x52, seed.seed[CRYPTO_SEED_SIZE - 1]);
}

TEST(parser, crypto_eckey_deserialize)
{
    // https://github.com/BlockchainCommons/Research/blob/master/papers/urc-2020-006-urtypes.md#partially-signed-bitcoin-transaction-psbt-crypto-psbt
    const char *hex = "a202f50358208c05c4b4f3e88840a4f4b5f155cfd69473ea169f3d0431b7a6787a23777f08aa";
    uint8_t raw[BUFLEN];
    size_t len = h2b(hex, BUFLEN, (uint8_t *)&raw);
    TEST_ASSERT_GREATER_THAN_INT(0, len);

    crypto_eckey eckey;
    int err = urc_crypto_eckey_deserialize(raw, len, &eckey);
    TEST_ASSERT_EQUAL(URC_OK, err);
    TEST_ASSERT_EQUAL(eckey_type_private, eckey.type);
    TEST_ASSERT_EQUAL_HEX(0x8c, eckey.key.prvate[0]);
    TEST_ASSERT_EQUAL_HEX(0xaa, eckey.key.prvate[CRYPTO_ECKEY_PRIVATE_SIZE - 1]);
}
