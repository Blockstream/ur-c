#include "bcr/bcr.h"
#include "unity.h"
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "helpers.h"

#define BUFSIZE 500

void setUp() {}
void tearDown() {}

void test_crypto_seed_parse() {
    // https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2020-006-urtypes.md#exampletest-vector-1
    const char *hex = "a20150c7098580125e2ab0981253468b2dbc5202d8641947da";
    uint8_t raw[BUFSIZE];
    int len = h2b(hex, (uint8_t *)(&raw), BUFSIZE);
    TEST_ASSERT_GREATER_THAN_INT(0, len);

    crypto_seed seed;
    bcr_error err = parse_seed(raw, len, &seed);
    TEST_ASSERT_EQUAL(bcr_error_tag_noerror, err.tag);
    TEST_ASSERT_EQUAL(18394, seed.creation_date);
    TEST_ASSERT_EQUAL(0xc7, seed.seed[0]);
    TEST_ASSERT_EQUAL(0x52, seed.seed[CRYPTO_SEED_SIZE - 1]);
}

void test_crypto_psbt_parse() {
    // https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2020-006-urtypes.md#partially-signed-bitcoin-transaction-psbt-crypto-psbt
    const char *hex = "58a770736274ff01009a020000000258e87a21b56daf0c23be8e7070456c336f7cbaa5c8757924f545887bb2abdd7500"
                      "00000000ffffffff838d0427d0ec650a68aa46bb0b098aea4422c071b2ca78352a077959d07cea1d0100000000ffffff"
                      "ff0270aaf00800000000160014d85c2b71d0060b09c9886aeb815e50991dda124d00e1f5050000000016001400aea9a2"
                      "e5f0f876a588df5546e8742d1d87008f000000000000000000";
    uint8_t raw[BUFSIZE];
    int len = h2b(hex, (uint8_t *)(&raw), BUFSIZE);
    TEST_ASSERT_GREATER_THAN_INT(0, len);

    crypto_psbt psbt;
    uint8_t buffer[1000];
    psbt.buffer = buffer;
    psbt.buffer_size = 1000;
    bcr_error err = parse_psbt(raw, len, &psbt);
    TEST_ASSERT_EQUAL(bcr_error_tag_noerror, err.tag);
    TEST_ASSERT_EQUAL(167, psbt.psbt_len);
    TEST_ASSERT_EQUAL(0x70, psbt.buffer[0]);
    TEST_ASSERT_EQUAL(0x00, psbt.buffer[psbt.psbt_len - 1]);
}

void test_crypto_eckey_parse() {
    // https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2020-006-urtypes.md#partially-signed-bitcoin-transaction-psbt-crypto-psbt
    const char *hex = "a202f50358208c05c4b4f3e88840a4f4b5f155cfd69473ea169f3d0431b7a6787a23777f08aa";
    uint8_t raw[BUFSIZE];
    int len = h2b(hex, (uint8_t *)(&raw), BUFSIZE);
    TEST_ASSERT_GREATER_THAN_INT(0, len);

    crypto_eckey eckey;
    bcr_error err = parse_eckey(raw, len, &eckey);
    TEST_ASSERT_EQUAL(key_type_private, eckey.type);
}



int main() {
    UNITY_BEGIN();
    RUN_TEST(test_crypto_seed_parse);
    RUN_TEST(test_crypto_psbt_parse);
    RUN_TEST(test_crypto_eckey_parse);
    return UNITY_END();
}
