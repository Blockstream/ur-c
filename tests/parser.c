
#include "unity.h"

#include "ur-c/urc.h"

#include "helpers.h"

#define BUFSIZE 500

void setUp() {}
void tearDown() {}

void test_crypto_seed_parse() {
    // https://github.com/BlockchainCommons/Research/blob/master/papers/urc-2020-006-urtypes.md#exampletest-vector-1
    const char *hex = "a20150c7098580125e2ab0981253468b2dbc5202d8641947da";
    uint8_t raw[BUFSIZE];
    int len = h2b(hex, BUFSIZE, (uint8_t *)&raw);
    TEST_ASSERT_GREATER_THAN_INT(0, len);

    crypto_seed seed;
    urc_error err = parse_seed(len, raw, &seed);
    TEST_ASSERT_EQUAL(urc_error_tag_noerror, err.tag);
    TEST_ASSERT_EQUAL(18394, seed.creation_date);
    TEST_ASSERT_EQUAL(0xc7, seed.seed[0]);
    TEST_ASSERT_EQUAL(0x52, seed.seed[CRYPTO_SEED_SIZE - 1]);
}

void test_crypto_psbt_parse() {
    // https://github.com/BlockchainCommons/Research/blob/master/papers/urc-2020-006-urtypes.md#partially-signed-bitcoin-transaction-psbt-crypto-psbt
    const char *hex = "58a770736274ff01009a020000000258e87a21b56daf0c23be8e7070456c336f7cbaa5c8757924f545887bb2abdd7500"
                      "00000000ffffffff838d0427d0ec650a68aa46bb0b098aea4422c071b2ca78352a077959d07cea1d0100000000ffffff"
                      "ff0270aaf00800000000160014d85c2b71d0060b09c9886aeb815e50991dda124d00e1f5050000000016001400aea9a2"
                      "e5f0f876a588df5546e8742d1d87008f000000000000000000";
    uint8_t raw[BUFSIZE];
    int len = h2b(hex, BUFSIZE, (uint8_t *)&raw);
    TEST_ASSERT_GREATER_THAN_INT(0, len);

    crypto_psbt psbt;
    uint8_t buffer[1000];
    psbt.buffer = buffer;
    psbt.buffer_size = 1000;
    urc_error err = parse_psbt(len, raw, &psbt);
    TEST_ASSERT_EQUAL(urc_error_tag_noerror, err.tag);
    TEST_ASSERT_EQUAL(167, psbt.psbt_len);
    TEST_ASSERT_EQUAL(0x70, psbt.buffer[0]);
    TEST_ASSERT_EQUAL(0x00, psbt.buffer[psbt.psbt_len - 1]);
}

void test_crypto_eckey_parse() {
    // https://github.com/BlockchainCommons/Research/blob/master/papers/urc-2020-006-urtypes.md#partially-signed-bitcoin-transaction-psbt-crypto-psbt
    const char *hex = "a202f50358208c05c4b4f3e88840a4f4b5f155cfd69473ea169f3d0431b7a6787a23777f08aa";
    uint8_t raw[BUFSIZE];
    int len = h2b(hex, BUFSIZE, (uint8_t *)&raw);
    TEST_ASSERT_GREATER_THAN_INT(0, len);

    crypto_eckey eckey;
    urc_error err = parse_eckey(len, raw, &eckey);
    TEST_ASSERT_EQUAL(urc_error_tag_noerror, err.tag);
    TEST_ASSERT_EQUAL(eckey_type_private, eckey.type);
    TEST_ASSERT_EQUAL(0x8c, eckey.key.private[0]);
    TEST_ASSERT_EQUAL(0xaa, eckey.key.private[CRYPTO_ECKEY_PRIVATE_SIZE - 1]);
}

void test_crypto_hdkey_parse_1() {
    // https://github.com/BlockchainCommons/Research/blob/master/papers/urc-2020-007-hdkey.md#exampletest-vector-1
    const char *hex = "a301f503582100e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35045820873dff81c02f525623fd1f"
                      "e5167eac3a55a049de3d314bb42ee227ffed37d508";
    uint8_t raw[BUFSIZE];
    int len = h2b(hex, BUFSIZE, (uint8_t *)(&raw));
    TEST_ASSERT_GREATER_THAN_INT(0, len);

    crypto_hdkey hdkey;
    urc_error err = parse_hdkey(len, raw, &hdkey);
    TEST_ASSERT_EQUAL(urc_error_tag_noerror, err.tag);
    TEST_ASSERT_EQUAL(hdkey_type_master, hdkey.type);
    TEST_ASSERT_EQUAL(0x00, hdkey.key.master.keydata[0]);
    TEST_ASSERT_EQUAL(0x35, hdkey.key.master.keydata[CRYPTO_HDKEY_KEYDATA_SIZE - 1]);
    TEST_ASSERT_EQUAL(0x87, hdkey.key.master.chaincode[0]);
    TEST_ASSERT_EQUAL(0x08, hdkey.key.master.chaincode[CRYPTO_HDKEY_CHAINCODE_SIZE - 1]);
}

void test_crypto_hdkey_parse_2() {
    // https://github.com/BlockchainCommons/Research/blob/master/papers/urc-2020-007-hdkey.md#exampletest-vector-2
    const char *hex = "a5035821026fe2355745bb2db3630bbc80ef5d58951c963c841f54170ba6e5c12be7fc12a6045820ced155c72456255881793514ed"
                      "c5bd9447e7f74abb88c6d6b6480fd016ee8c8505d90131a1020106d90130a1018a182cf501f501f500f401f4081ae9181cf3";
    uint8_t raw[BUFSIZE];
    int len = h2b(hex, BUFSIZE, (uint8_t *)(&raw));
    TEST_ASSERT_GREATER_THAN_INT(0, len);

    crypto_hdkey hdkey;
    urc_error err = parse_hdkey(len, raw, &hdkey);
    TEST_ASSERT_EQUAL(urc_error_tag_noerror, err.tag);
    TEST_ASSERT_EQUAL(hdkey_type_derived, hdkey.type);

    TEST_ASSERT_FALSE(hdkey.key.derived.is_private);

    TEST_ASSERT_EQUAL(0x02, hdkey.key.derived.keydata[0]);
    TEST_ASSERT_EQUAL(0xa6, hdkey.key.derived.keydata[CRYPTO_HDKEY_KEYDATA_SIZE - 1]);

    TEST_ASSERT_TRUE(hdkey.key.derived.valid_chaincode);
    TEST_ASSERT_EQUAL(0xce, hdkey.key.derived.chaincode[0]);
    TEST_ASSERT_EQUAL(0x85, hdkey.key.derived.chaincode[CRYPTO_HDKEY_CHAINCODE_SIZE - 1]);

    TEST_ASSERT_TRUE(hdkey.key.derived.valid_useinfo);
    TEST_ASSERT_EQUAL(CRYPTO_COININFO_TYPE_BTC, hdkey.key.derived.useinfo.type);
    TEST_ASSERT_EQUAL(CRYPTO_COININFO_TESTNET_BTC, hdkey.key.derived.useinfo.network);

    TEST_ASSERT_TRUE(hdkey.key.derived.valid_origin);
    TEST_ASSERT_EQUAL(5, hdkey.key.derived.origin.components_count);

    TEST_ASSERT_EQUAL(path_component_type_index, hdkey.key.derived.origin.components[0].type);
    TEST_ASSERT_EQUAL(44, hdkey.key.derived.origin.components[0].component.index.index);
    TEST_ASSERT_TRUE(hdkey.key.derived.origin.components[0].component.index.is_hardened);

    TEST_ASSERT_EQUAL(path_component_type_index, hdkey.key.derived.origin.components[1].type);
    TEST_ASSERT_EQUAL(1, hdkey.key.derived.origin.components[1].component.index.index);
    TEST_ASSERT_TRUE(hdkey.key.derived.origin.components[1].component.index.is_hardened);

    TEST_ASSERT_EQUAL(path_component_type_index, hdkey.key.derived.origin.components[2].type);
    TEST_ASSERT_EQUAL(1, hdkey.key.derived.origin.components[2].component.index.index);
    TEST_ASSERT_TRUE(hdkey.key.derived.origin.components[2].component.index.is_hardened);

    TEST_ASSERT_EQUAL(path_component_type_index, hdkey.key.derived.origin.components[3].type);
    TEST_ASSERT_EQUAL(0, hdkey.key.derived.origin.components[3].component.index.index);
    TEST_ASSERT_FALSE(hdkey.key.derived.origin.components[3].component.index.is_hardened);

    TEST_ASSERT_EQUAL(path_component_type_index, hdkey.key.derived.origin.components[4].type);
    TEST_ASSERT_EQUAL(1, hdkey.key.derived.origin.components[4].component.index.index);
    TEST_ASSERT_FALSE(hdkey.key.derived.origin.components[4].component.index.is_hardened);

    TEST_ASSERT_EQUAL(0, hdkey.key.derived.origin.source_fingerprint);
    TEST_ASSERT_EQUAL(0, hdkey.key.derived.origin.depth);

    TEST_ASSERT_FALSE(hdkey.key.derived.valid_children);

    TEST_ASSERT_EQUAL(3910671603, hdkey.key.derived.parent_fingerprint);
}

/*
void test_crypto_output_parse_p2pkh() {
    // https://github.com/BlockchainCommons/Research/blob/master/papers/urc-2020-010-output-desc.md#exampletest-vector-1
    const char *hex = "d90193d90132a103582102c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";
    uint8_t raw[BUFSIZE];
    int len = h2b(hex, (uint8_t *)(&raw), BUFSIZE);
    TEST_ASSERT_GREATER_THAN_INT(0, len);

    crypto_output output;
    urc_error err = parse_output(raw, len, &output);
    TEST_ASSERT_EQUAL(urc_error_tag_noerror, err.tag);
    TEST_ASSERT_EQUAL(output_type_p2pkh, output.type);
    TEST_ASSERT_EQUAL(p2pkh_type_eckey, output.output.p2pkh.type);
    TEST_ASSERT_EQUAL(eckey_type_public_compressed, output.output.p2pkh.key.eckey.type);
    TEST_ASSERT_EQUAL(0x02, output.output.p2pkh.key.eckey.key.public_compressed[0]);
    TEST_ASSERT_EQUAL(0xe5,
                      output.output.p2pkh.key.eckey.key.public_compressed[CRYPTO_ECKEY_PUBLIC_COMPRESSED_SIZE - 1]);
}

void test_crypto_output_parse_p2sh_p2wpkh() {
    // https://github.com/BlockchainCommons/Research/blob/master/papers/urc-2020-010-output-desc.md#exampletest-vector-1
    const char *hex = "d90190d90194d90132a103582103fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556";
    uint8_t raw[BUFSIZE];
    int len = h2b(hex, (uint8_t *)(&raw), BUFSIZE);
    TEST_ASSERT_GREATER_THAN_INT(0, len);

    crypto_output output;
    urc_error err = parse_output(raw, len, &output);
    // TEST_ASSERT_EQUAL(urc_error_tag_noerror, err.tag);
    // TEST_ASSERT_EQUAL(output_type_psh_p2wpkh, output.type);
    // TEST_ASSERT_EQUAL(key_type_public_compressed, output.output.ps.key.type);
    // TEST_ASSERT_EQUAL(0x02, output.output.p2pkh.key.eckey.public_uncompressed[0]);
    // TEST_ASSERT_EQUAL(0xe5, output.output.p2pkh.key.eckey.public_uncompressed[CRYPTO_ECKEY_PUBLIC_COMPRESSED_SIZE -
    // 1]);
}
*/

int main() {
    UNITY_BEGIN();
    RUN_TEST(test_crypto_seed_parse);
    RUN_TEST(test_crypto_psbt_parse);
    RUN_TEST(test_crypto_eckey_parse);
    RUN_TEST(test_crypto_hdkey_parse_1);
    RUN_TEST(test_crypto_hdkey_parse_2);
    // RUN_TEST(test_crypto_output_parse_p2pkh);
    // RUN_TEST(test_crypto_output_parse_p2sh_p2wpkh);
    return UNITY_END();
}
