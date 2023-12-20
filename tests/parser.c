
#include <string.h>
#include <valgrind/memcheck.h>

#include "unity_fixture.h"

#include "urc/urc.h"

#include "helpers.h"

#define BUFLEN 1000

TEST_GROUP(parser);

TEST_SETUP(parser) {}
TEST_TEAR_DOWN(parser) {}

void test_format_key_origin(const crypto_hdkey *key, const char *expected)
{
    size_t expected_len = strnlen(expected, BUFLEN);
    char keypath[BUFLEN];
    if (RUNNING_ON_VALGRIND) {
        for (size_t i = 0; i < expected_len; i++) {
            VALGRIND_MAKE_MEM_UNDEFINED(keypath, i);
            VALGRIND_MAKE_MEM_NOACCESS(&keypath[i], BUFLEN - i);
            int len = format_keyorigin(key, (char *)keypath, i);
            TEST_ASSERT_GREATER_OR_EQUAL(i, len);
        }
        VALGRIND_MAKE_MEM_UNDEFINED(keypath, BUFLEN);
    } else {
        // buffer too short
        char keypath[10];
        int len = format_keyorigin(key, (char *)keypath, 10);
        TEST_ASSERT_GREATER_OR_EQUAL(10, len);
    }

    int len = format_keyorigin(key, (char *)keypath, BUFLEN);
    TEST_ASSERT_GREATER_THAN_INT(0, len);
    TEST_ASSERT_EQUAL(expected_len, len);
    TEST_ASSERT_EQUAL_STRING(expected, keypath);
}

TEST(parser, crypto_seed_parse)
{
    // https://github.com/BlockchainCommons/Research/blob/master/papers/urc-2020-006-urtypes.md#exampletest-vector-1
    const char *hex = "a20150c7098580125e2ab0981253468b2dbc5202d8641947da";
    uint8_t raw[BUFLEN];
    size_t len = h2b(hex, BUFLEN, (uint8_t *)&raw);
    TEST_ASSERT_GREATER_THAN_INT(0, len);

    crypto_seed seed;
    int err = urc_crypto_seed_parse(raw, len, &seed);
    TEST_ASSERT_EQUAL(URC_OK, err);
    TEST_ASSERT_EQUAL(18394, seed.creation_date);
    TEST_ASSERT_EQUAL_HEX(0xc7, seed.seed[0]);
    TEST_ASSERT_EQUAL_HEX(0x52, seed.seed[CRYPTO_SEED_SIZE - 1]);
}

TEST(parser, crypto_psbt_parse)
{
    // https://github.com/BlockchainCommons/Research/blob/master/papers/urc-2020-006-urtypes.md#partially-signed-bitcoin-transaction-psbt-crypto-psbt
    const char *hex = "58a770736274ff01009a020000000258e87a21b56daf0c23be8e7070456c336f7cbaa5c8757924f545887bb2abdd7500"
                      "00000000ffffffff838d0427d0ec650a68aa46bb0b098aea4422c071b2ca78352a077959d07cea1d0100000000ffffff"
                      "ff0270aaf00800000000160014d85c2b71d0060b09c9886aeb815e50991dda124d00e1f5050000000016001400aea9a2"
                      "e5f0f876a588df5546e8742d1d87008f000000000000000000";
    uint8_t raw[BUFLEN];
    size_t len = h2b(hex, BUFLEN, (uint8_t *)&raw);
    TEST_ASSERT_GREATER_THAN_INT(0, len);

    crypto_psbt psbt;
    uint8_t buffer[1000];
    psbt.buffer = buffer;
    psbt.buffer_size = BUFLEN;
    int err = urc_crypto_psbt_parse(raw, len, &psbt);
    TEST_ASSERT_EQUAL(URC_OK, err);
    TEST_ASSERT_EQUAL(167, psbt.psbt_len);
    TEST_ASSERT_EQUAL_HEX(0x70, psbt.buffer[0]);
    TEST_ASSERT_EQUAL_HEX(0x00, psbt.buffer[psbt.psbt_len - 1]);
}

TEST(parser, crypto_eckey_parse)
{
    // https://github.com/BlockchainCommons/Research/blob/master/papers/urc-2020-006-urtypes.md#partially-signed-bitcoin-transaction-psbt-crypto-psbt
    const char *hex = "a202f50358208c05c4b4f3e88840a4f4b5f155cfd69473ea169f3d0431b7a6787a23777f08aa";
    uint8_t raw[BUFLEN];
    size_t len = h2b(hex, BUFLEN, (uint8_t *)&raw);
    TEST_ASSERT_GREATER_THAN_INT(0, len);

    crypto_eckey eckey;
    int err = urc_crypto_eckey_parse(raw, len, &eckey);
    TEST_ASSERT_EQUAL(URC_OK, err);
    TEST_ASSERT_EQUAL(eckey_type_private, eckey.type);
    TEST_ASSERT_EQUAL_HEX(0x8c, eckey.key.prvate[0]);
    TEST_ASSERT_EQUAL_HEX(0xaa, eckey.key.prvate[CRYPTO_ECKEY_PRIVATE_SIZE - 1]);
}

TEST(parser, crypto_hdkey_parse_1)
{
    // https://github.com/BlockchainCommons/Research/blob/master/papers/urc-2020-007-hdkey.md#exampletest-vector-1
    const char *hex = "a301f503582100e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35045820873dff81c02f525623fd1f"
                      "e5167eac3a55a049de3d314bb42ee227ffed37d508";
    uint8_t raw[BUFLEN];
    size_t len = h2b(hex, BUFLEN, (uint8_t *)(&raw));
    TEST_ASSERT_GREATER_THAN_INT(0, len);

    crypto_hdkey hdkey;
    int err = urc_crypto_hdkey_parse(raw, len, &hdkey);
    TEST_ASSERT_EQUAL(URC_OK, err);
    TEST_ASSERT_EQUAL(hdkey_type_master, hdkey.type);
    TEST_ASSERT_EQUAL_HEX(0x00, hdkey.key.master.keydata[0]);
    TEST_ASSERT_EQUAL_HEX(0x35, hdkey.key.master.keydata[CRYPTO_HDKEY_KEYDATA_SIZE - 1]);
    TEST_ASSERT_EQUAL_HEX(0x87, hdkey.key.master.chaincode[0]);
    TEST_ASSERT_EQUAL_HEX(0x08, hdkey.key.master.chaincode[CRYPTO_HDKEY_CHAINCODE_SIZE - 1]);

    uint8_t bip32[BIP32_SERIALIZED_LEN];
    bool ok = bip32_serialize(&hdkey, bip32);
    TEST_ASSERT_TRUE(ok);
    uint8_t expected[] = {0x04, 0x88, 0xad, 0xe4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x87, 0x3d, 0xff,
                          0x81, 0xc0, 0x2f, 0x52, 0x56, 0x23, 0xfd, 0x1f, 0xe5, 0x16, 0x7e, 0xac, 0x3a, 0x55, 0xa0, 0x49,
                          0xde, 0x3d, 0x31, 0x4b, 0xb4, 0x2e, 0xe2, 0x27, 0xff, 0xed, 0x37, 0xd5, 0x08, 0x00, 0xe8, 0xf3,
                          0x2e, 0x72, 0x3d, 0xec, 0xf4, 0x05, 0x1a, 0xef, 0xac, 0x8e, 0x2c, 0x93, 0xc9, 0xc5, 0xb2, 0x14,
                          0x31, 0x38, 0x17, 0xcd, 0xb0, 0x1a, 0x14, 0x94, 0xb9, 0x17, 0xc8, 0x43, 0x6b, 0x35};
    TEST_ASSERT_EQUAL_UINT8_ARRAY(expected, bip32, BIP32_SERIALIZED_LEN);

    test_format_key_origin(&hdkey, "[00000000]");
    {
        char *out;
        err = urc_bip32_tobase58(&hdkey, &out);
        TEST_ASSERT_EQUAL(URC_OK, err);
        const char *expected =
            "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";
        TEST_ASSERT_EQUAL_STRING(expected, out);
        urc_string_free(out);
    }
}

TEST(parser, crypto_hdkey_parse_2)
{
    // https://github.com/BlockchainCommons/Research/blob/master/papers/urc-2020-007-hdkey.md#exampletest-vector-2
    const char *hex = "a5035821026fe2355745bb2db3630bbc80ef5d58951c963c841f54170ba6e5c12be7fc12a6045820ced155c72456255881793514ed"
                      "c5bd9447e7f74abb88c6d6b6480fd016ee8c8505d90131a1020106d90130a1018a182cf501f501f500f401f4081ae9181cf3";
    uint8_t raw[BUFLEN];
    size_t len = h2b(hex, BUFLEN, (uint8_t *)(&raw));
    TEST_ASSERT_GREATER_THAN_INT(0, len);

    crypto_hdkey hdkey;
    int err = urc_crypto_hdkey_parse(raw, len, &hdkey);
    TEST_ASSERT_EQUAL(URC_OK, err);
    TEST_ASSERT_EQUAL(hdkey_type_derived, hdkey.type);

    TEST_ASSERT_FALSE(hdkey.key.derived.is_private);

    TEST_ASSERT_EQUAL_HEX(0x02, hdkey.key.derived.keydata[0]);
    TEST_ASSERT_EQUAL_HEX(0xa6, hdkey.key.derived.keydata[CRYPTO_HDKEY_KEYDATA_SIZE - 1]);

    TEST_ASSERT_TRUE(hdkey.key.derived.valid_chaincode);
    TEST_ASSERT_EQUAL_HEX(0xce, hdkey.key.derived.chaincode[0]);
    TEST_ASSERT_EQUAL_HEX(0x85, hdkey.key.derived.chaincode[CRYPTO_HDKEY_CHAINCODE_SIZE - 1]);

    TEST_ASSERT_EQUAL(CRYPTO_COININFO_TYPE_BTC, hdkey.key.derived.useinfo.type);
    TEST_ASSERT_EQUAL(CRYPTO_COININFO_TESTNET, hdkey.key.derived.useinfo.network);

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

    TEST_ASSERT_EQUAL(0, hdkey.key.derived.children.components_count);

    TEST_ASSERT_EQUAL(3910671603, hdkey.key.derived.parent_fingerprint);

    uint8_t bip32[BIP32_SERIALIZED_LEN];
    bool ok = bip32_serialize(&hdkey, bip32);
    TEST_ASSERT_TRUE(ok);
    uint8_t expected[] = {0x04, 0x35, 0x87, 0xcf, 0x05, 0xe9, 0x18, 0x1c, 0xf3, 0x00, 0x00, 0x00, 0x01, 0xce, 0xd1, 0x55,
                          0xc7, 0x24, 0x56, 0x25, 0x58, 0x81, 0x79, 0x35, 0x14, 0xed, 0xc5, 0xbd, 0x94, 0x47, 0xe7, 0xf7,
                          0x4a, 0xbb, 0x88, 0xc6, 0xd6, 0xb6, 0x48, 0x0f, 0xd0, 0x16, 0xee, 0x8c, 0x85, 0x02, 0x6f, 0xe2,
                          0x35, 0x57, 0x45, 0xbb, 0x2d, 0xb3, 0x63, 0x0b, 0xbc, 0x80, 0xef, 0x5d, 0x58, 0x95, 0x1c, 0x96,
                          0x3c, 0x84, 0x1f, 0x54, 0x17, 0x0b, 0xa6, 0xe5, 0xc1, 0x2b, 0xe7, 0xfc, 0x12, 0xa6};
    TEST_ASSERT_EQUAL_UINT8_ARRAY(expected, bip32, BIP32_SERIALIZED_LEN);

    test_format_key_origin(&hdkey, "[e9181cf3/44'/1'/1'/0/1]");
    {
        char derivationpath[BUFLEN];
        int len = format_keyderivationpath(&hdkey, (char *)&derivationpath, BUFLEN);
        TEST_ASSERT_EQUAL(0, len);
    }
    {
        char *out;
        err = urc_bip32_tobase58(&hdkey, &out);
        TEST_ASSERT_EQUAL(URC_OK, err);
        const char *expected =
            "tpubDHW3GtnVrTatx38EcygoSf9UhUd9Dx1rht7FAL8unrMo8r2NWhJuYNqDFS7cZFVbDaxJkV94MLZAr86XFPsAPYcoHWJ7sWYsrmHDw5sKQ2K";
        TEST_ASSERT_EQUAL_STRING(expected, out);
        urc_string_free(out);
    }
}

TEST(parser, crypto_output_parse_1)
{
    // https://github.com/BlockchainCommons/Research/blob/master/papers/urc-2020-010-output-desc.md#exampletest-vector-1
    const char *hex = "d90193d90132a103582102c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";
    uint8_t raw[BUFLEN];
    size_t len = h2b(hex, BUFLEN, (uint8_t *)(&raw));
    TEST_ASSERT_GREATER_THAN_INT(0, len);

    crypto_output output;
    int err = urc_crypto_output_parse(raw, len, &output);
    TEST_ASSERT_EQUAL(URC_OK, err);
    TEST_ASSERT_EQUAL(output_type__, output.type);
    TEST_ASSERT_EQUAL(keyexp_keytype_eckey, output.output.key.keytype);
    TEST_ASSERT_EQUAL(eckey_type_public_compressed, output.output.key.key.eckey.type);
    TEST_ASSERT_EQUAL_HEX(0x02, output.output.key.key.eckey.key.public_compressed[0]);
    TEST_ASSERT_EQUAL_HEX(0xe5, output.output.key.key.eckey.key.public_compressed[CRYPTO_ECKEY_PUBLIC_COMPRESSED_SIZE - 1]);
}

TEST(parser, crypto_output_parse_2)
{
    // https://github.com/BlockchainCommons/Research/blob/master/papers/urc-2020-010-output-desc.md#exampletest-vector-1
    const char *hex = "d90190d90194d90132a103582103fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556";
    uint8_t raw[BUFLEN];
    size_t len = h2b(hex, BUFLEN, (uint8_t *)(&raw));
    TEST_ASSERT_GREATER_THAN_INT(0, len);

    crypto_output output;
    int err = urc_crypto_output_parse(raw, len, &output);
    TEST_ASSERT_EQUAL(URC_OK, err);
    TEST_ASSERT_EQUAL(output_type_sh, output.type);
    TEST_ASSERT_EQUAL(keyexp_type_wpkh, output.output.key.type);
    TEST_ASSERT_EQUAL(keyexp_keytype_eckey, output.output.key.keytype);
    TEST_ASSERT_EQUAL(eckey_type_public_compressed, output.output.key.key.eckey.type);
    TEST_ASSERT_EQUAL_HEX(0x03, output.output.key.key.eckey.key.public_compressed[0]);
    TEST_ASSERT_EQUAL(0x56, output.output.key.key.eckey.key.public_compressed[CRYPTO_ECKEY_PUBLIC_COMPRESSED_SIZE - 1]);
}

TEST(parser, crypto_output_parse_3)
{
    // https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2020-010-output-desc.md#exampletest-vector-3
    const char *hex = "d90190d90196a201020282d90132a1035821022f01e5e15cca351daff3843fb70f3c2f0a1bdd05e5af888a67784ef3e10a2a01d901"
                      "32a103582103acd484e2f0c7f65309ad178a9f559abde09796974c57e714c35f110dfc27ccbe";
    uint8_t raw[BUFLEN];
    size_t len = h2b(hex, BUFLEN, (uint8_t *)(&raw));
    TEST_ASSERT_GREATER_THAN_INT(0, len);

    crypto_output output;
    int err = urc_crypto_output_parse(raw, len, &output);
    TEST_ASSERT_EQUAL(URC_EUNHANDLEDCASE, err);
}

TEST(parser, crypto_output_parse_4)
{
    // https://github.com/BlockchainCommons/Research/blob/master/papers/urc-2020-010-output-desc.md#exampletest-vector-4
    const char *hex =
        "d90193d9012fa503582102d2b36900396c9282fa14628566582f206a5dd0bcc8d5e892611806cafb0301f0045820637807030d55d01f9a0cb3a78395"
        "15d796bd07706386a6eddf06cc29a65a0e2906d90130a30186182cf500f500f5021ad34db33f030407d90130a1018401f480f4081a78412e3a";
    uint8_t raw[BUFLEN];
    size_t len = h2b(hex, BUFLEN, (uint8_t *)(&raw));
    TEST_ASSERT_GREATER_THAN_INT(0, len);

    crypto_output output;
    int err = urc_crypto_output_parse(raw, len, &output);
    TEST_ASSERT_EQUAL(URC_OK, err);
    TEST_ASSERT_EQUAL(output_type__, output.type);
    TEST_ASSERT_EQUAL(keyexp_type_pkh, output.output.key.type);
    TEST_ASSERT_EQUAL(keyexp_keytype_hdkey, output.output.key.keytype);
    crypto_hdkey *key = &output.output.key.key.hdkey;
    TEST_ASSERT_EQUAL(hdkey_type_derived, key->type);
    TEST_ASSERT_EQUAL_HEX(0x02, key->key.derived.keydata[0]);
    TEST_ASSERT_EQUAL_HEX(0xf0, key->key.derived.keydata[CRYPTO_HDKEY_KEYDATA_SIZE - 1]);

    TEST_ASSERT_TRUE(key->key.derived.valid_chaincode);
    TEST_ASSERT_EQUAL_HEX(0x63, key->key.derived.chaincode[0]);
    TEST_ASSERT_EQUAL_HEX(0x29, key->key.derived.chaincode[CRYPTO_HDKEY_CHAINCODE_SIZE - 1]);
    //
    TEST_ASSERT_EQUAL(3, key->key.derived.origin.components_count);
    //
    TEST_ASSERT_EQUAL(path_component_type_index, key->key.derived.origin.components[0].type);
    TEST_ASSERT_TRUE(key->key.derived.origin.components[0].component.index.is_hardened);
    TEST_ASSERT_EQUAL(44, key->key.derived.origin.components[0].component.index.index);

    TEST_ASSERT_EQUAL(path_component_type_index, key->key.derived.origin.components[1].type);
    TEST_ASSERT_TRUE(key->key.derived.origin.components[1].component.index.is_hardened);
    TEST_ASSERT_EQUAL(0, key->key.derived.origin.components[1].component.index.index);

    TEST_ASSERT_EQUAL(path_component_type_index, key->key.derived.origin.components[2].type);
    TEST_ASSERT_TRUE(key->key.derived.origin.components[2].component.index.is_hardened);
    TEST_ASSERT_EQUAL(0, key->key.derived.origin.components[2].component.index.index);

    TEST_ASSERT_EQUAL(2, key->key.derived.children.components_count);

    TEST_ASSERT_EQUAL(path_component_type_index, key->key.derived.children.components[0].type);
    TEST_ASSERT_FALSE(key->key.derived.children.components[0].component.index.is_hardened);
    TEST_ASSERT_EQUAL(1, key->key.derived.children.components[0].component.index.index);

    TEST_ASSERT_EQUAL(path_component_type_wildcard, key->key.derived.children.components[1].type);
    TEST_ASSERT_FALSE(key->key.derived.children.components[1].component.wildcard.is_hardened);

    TEST_ASSERT_EQUAL(2017537594, key->key.derived.parent_fingerprint);

    uint8_t bip32[BIP32_SERIALIZED_LEN];
    bool ok = bip32_serialize(key, bip32);
    TEST_ASSERT_TRUE(ok);
    uint8_t expected[] = {0x04, 0x88, 0xb2, 0x1e, 0x04, 0x78, 0x41, 0x2e, 0x3a, 0xff, 0xff, 0xff, 0xfe, 0x63, 0x78, 0x07,
                          0x03, 0x0d, 0x55, 0xd0, 0x1f, 0x9a, 0x0c, 0xb3, 0xa7, 0x83, 0x95, 0x15, 0xd7, 0x96, 0xbd, 0x07,
                          0x70, 0x63, 0x86, 0xa6, 0xed, 0xdf, 0x06, 0xcc, 0x29, 0xa6, 0x5a, 0x0e, 0x29, 0x02, 0xd2, 0xb3,
                          0x69, 0x00, 0x39, 0x6c, 0x92, 0x82, 0xfa, 0x14, 0x62, 0x85, 0x66, 0x58, 0x2f, 0x20, 0x6a, 0x5d,
                          0xd0, 0xbc, 0xc8, 0xd5, 0xe8, 0x92, 0x61, 0x18, 0x06, 0xca, 0xfb, 0x03, 0x01, 0xf0};
    TEST_ASSERT_EQUAL_UINT8_ARRAY(expected, bip32, BIP32_SERIALIZED_LEN);

    test_format_key_origin(key, "[d34db33f/44'/0'/0']");
    {
        char derivationpath[BUFLEN];
        const char *expected = "/1/*";
        int len = format_keyderivationpath(key, (char *)&derivationpath, BUFLEN);
        TEST_ASSERT_GREATER_THAN_INT(0, len);
        TEST_ASSERT_LESS_THAN(BUFLEN, len);
        TEST_ASSERT_EQUAL_STRING(expected, derivationpath);
    }
    {
        char *out;
        err = urc_bip32_tobase58(key, &out);
        TEST_ASSERT_EQUAL(URC_OK, err);
        const char *expected =
            "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL";
        TEST_ASSERT_EQUAL_STRING(expected, out);
        urc_string_free(out);
    }
}

TEST(parser, crypto_output_parse_5)
{
    // https://github.com/BlockchainCommons/Research/blob/master/papers/urc-2020-010-output-desc.md#exampletest-vector-5
    const char *hex = "d90191d90196a201010282d9012fa403582103cbcaa9c98c877a26977d00825c956a238e8dddfbd322cce4f74b0b5bd6ace4a70458"
                      "2060499f801b896d83179a4374aeb7822aaeaceaa0db1f85ee3e904c4defbd968906d90130a20180030007d90130a1018601f400f4"
                      "80f4d9012fa403582102fc9e5af0ac8d9b3cecfe2a888e2117ba3d089d8585886c9c826b6b22a98d12ea045820f0909affaa7ee7ab"
                      "e5dd4e100598d4dc53cd709d5a5c2cac40e7412f232f7c9c06d90130a2018200f4021abd16bee507d90130a1018600f400f480f4";
    uint8_t raw[BUFLEN];
    size_t len = h2b(hex, BUFLEN, (uint8_t *)(&raw));
    TEST_ASSERT_GREATER_THAN_INT(0, len);

    crypto_output output;
    int err = urc_crypto_output_parse(raw, len, &output);
    TEST_ASSERT_EQUAL(URC_EUNHANDLEDCASE, err);
}

TEST(parser, crypto_account_parse)
{
    // https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2020-015-account.md#exampletest-vector
    const char *hex =
        "a2011a37b5eed40287d90134d90193d9012fa403582103eb3e2863911826374de86c231a4b76f0b89dfa174afb78d7f478199884d9dd320458206456"
        "a5df2db0f6d9af72b2a1af4b25f45200ed6fcc29c3440b311d4796b70b5b06d90130a20186182cf500f500f5021a37b5eed4081a99f9cdf7d90134d9"
        "0190d90194d9012fa403582102c7e4823730f6ee2cf864e2c352060a88e60b51a84e89e4c8c75ec22590ad6b690458209d2f86043276f9251a4a4f57"
        "7166a5abeb16b6ec61e226b5b8fa11038bfda42d06d90130a201861831f500f500f5021a37b5eed4081aa80f7cdbd90134d90194d9012fa403582103"
        "fd433450b6924b4f7efdd5d1ed017d364be95ab2b592dc8bddb3b00c1c24f63f04582072ede7334d5acf91c6fda622c205199c595a31f9218ed30792"
        "d301d5ee9e3a8806d90130a201861854f500f500f5021a37b5eed4081a0d5de1d7d90134d90190d9019ad9012fa4035821035ccd58b63a2cdc23d081"
        "2710603592e7457573211880cb59b1ef012e168e059a04582088d3299b448f87215d96b0c226235afc027f9e7dc700284f3e912a34daeb1a2306d901"
        "30a20182182df5021a37b5eed4081a37b5eed4d90134d90190d90191d9019ad9012fa4035821032c78ebfcabdac6d735a0820ef8732f2821b4fb84cd"
        "5d6b26526938f90c0507110458207953efe16a73e5d3f9f2d4c6e49bd88e22093bbd85be5a7e862a4b98a16e0ab606d90130a201881830f500f500f5"
        "01f5021a37b5eed4081a59b69b2ad90134d90191d9019ad9012fa40358210260563ee80c26844621b06b74070baf0e23fb76ce439d0237e87502ebbd"
        "3ca3460458202fa0e41c9dc43dc4518659bfcef935ba8101b57dbc0812805dd983bc1d34b81306d90130a201881830f500f500f502f5021a37b5eed4"
        "081a59b69b2ad90134d90199d9012fa403582102bbb97cf9efa176b738efd6ee1d4d0fa391a973394fbc16e4c5e78e536cd14d2d0458204b4693e1f7"
        "94206ed1355b838da24949a92b63d02e58910bf3bd3d9c242281e606d90130a201861856f500f500f5021a37b5eed4081acec7070c";
    uint8_t raw[BUFLEN];
    size_t len = h2b(hex, BUFLEN, (uint8_t *)(&raw));
    TEST_ASSERT_GREATER_THAN_INT(0, len);

    crypto_account account;
    int err = urc_crypto_account_parse(raw, len, &account);
    TEST_ASSERT_EQUAL(URC_ETAPROOTNOTSUPPORTED, err);

    TEST_ASSERT_EQUAL(934670036, account.master_fingerprint);
    TEST_ASSERT_EQUAL(6, account.descriptors_count);

    {
        crypto_output *output = &account.descriptors[0];
        TEST_ASSERT_EQUAL(output_type__, output->type);
        TEST_ASSERT_EQUAL(keyexp_type_pkh, output->output.key.type);
        TEST_ASSERT_EQUAL(keyexp_keytype_hdkey, output->output.key.keytype);
        crypto_hdkey *key = &output->output.key.key.hdkey;
        TEST_ASSERT_EQUAL(hdkey_type_derived, key->type);
        TEST_ASSERT_EQUAL_HEX(0x03, key->key.derived.keydata[0]);
        TEST_ASSERT_EQUAL_HEX(0x32, key->key.derived.keydata[CRYPTO_HDKEY_KEYDATA_SIZE - 1]);
        TEST_ASSERT_TRUE(key->key.derived.valid_chaincode);
        TEST_ASSERT_EQUAL_HEX(0x64, key->key.derived.chaincode[0]);
        TEST_ASSERT_EQUAL_HEX(0x5b, key->key.derived.chaincode[CRYPTO_HDKEY_CHAINCODE_SIZE - 1]);
        TEST_ASSERT_EQUAL(3, key->key.derived.origin.components_count);
        TEST_ASSERT_EQUAL(path_component_type_index, key->key.derived.origin.components[0].type);
        TEST_ASSERT_TRUE(key->key.derived.origin.components[0].component.index.is_hardened);
        TEST_ASSERT_EQUAL(44, key->key.derived.origin.components[0].component.index.index);
        TEST_ASSERT_EQUAL(path_component_type_index, key->key.derived.origin.components[1].type);
        TEST_ASSERT_TRUE(key->key.derived.origin.components[1].component.index.is_hardened);
        TEST_ASSERT_EQUAL(0, key->key.derived.origin.components[1].component.index.index);
        TEST_ASSERT_EQUAL(path_component_type_index, key->key.derived.origin.components[2].type);
        TEST_ASSERT_TRUE(key->key.derived.origin.components[2].component.index.is_hardened);
        TEST_ASSERT_EQUAL(0, key->key.derived.origin.components[2].component.index.index);
        TEST_ASSERT_EQUAL(934670036, key->key.derived.origin.source_fingerprint);
        TEST_ASSERT_EQUAL(0, key->key.derived.children.components_count);
        TEST_ASSERT_EQUAL(2583285239, key->key.derived.parent_fingerprint);

        uint8_t bip32[BIP32_SERIALIZED_LEN];
        bool ok = bip32_serialize(key, bip32);
        TEST_ASSERT_TRUE(ok);
        uint8_t expected[] = {0x04, 0x88, 0xb2, 0x1e, 0x03, 0x99, 0xf9, 0xcd, 0xf7, 0x80, 0x00, 0x00, 0x00, 0x64, 0x56, 0xa5,
                              0xdf, 0x2d, 0xb0, 0xf6, 0xd9, 0xaf, 0x72, 0xb2, 0xa1, 0xaf, 0x4b, 0x25, 0xf4, 0x52, 0x00, 0xed,
                              0x6f, 0xcc, 0x29, 0xc3, 0x44, 0x0b, 0x31, 0x1d, 0x47, 0x96, 0xb7, 0x0b, 0x5b, 0x03, 0xeb, 0x3e,
                              0x28, 0x63, 0x91, 0x18, 0x26, 0x37, 0x4d, 0xe8, 0x6c, 0x23, 0x1a, 0x4b, 0x76, 0xf0, 0xb8, 0x9d,
                              0xfa, 0x17, 0x4a, 0xfb, 0x78, 0xd7, 0xf4, 0x78, 0x19, 0x98, 0x84, 0xd9, 0xdd, 0x32};
        TEST_ASSERT_EQUAL_UINT8_ARRAY(expected, bip32, BIP32_SERIALIZED_LEN);

        test_format_key_origin(key, "[37b5eed4/44'/0'/0']");
        {
            char derivationpath[BUFLEN];
            int len = format_keyderivationpath(key, (char *)&derivationpath, BUFLEN);
            TEST_ASSERT_EQUAL(0, len);
        }
        {
            char *out;
            err = urc_bip32_tobase58(key, &out);
            TEST_ASSERT_EQUAL(URC_OK, err);
            const char *expected =
                "xpub6CnQkivUEH9bSbWVWfDLCtigKKgnSWGaVSRyCbN2QNBJzuvHT1vUQpgSpY1NiVvoeNEuVwk748Cn9G3NtbQB1aGGsEL7aYEnjVWgjj9tefu";
            TEST_ASSERT_EQUAL_STRING(expected, out);
            urc_string_free(out);
        }
    }
    {
        crypto_output *output = &account.descriptors[1];
        TEST_ASSERT_EQUAL(output_type_sh, output->type);
        TEST_ASSERT_EQUAL(keyexp_type_wpkh, output->output.key.type);
        TEST_ASSERT_EQUAL(keyexp_keytype_hdkey, output->output.key.keytype);
        crypto_hdkey *key = &output->output.key.key.hdkey;
        TEST_ASSERT_EQUAL(hdkey_type_derived, key->type);
        TEST_ASSERT_EQUAL_HEX(0x02, key->key.derived.keydata[0]);
        TEST_ASSERT_EQUAL_HEX(0x69, key->key.derived.keydata[CRYPTO_HDKEY_KEYDATA_SIZE - 1]);
        TEST_ASSERT_TRUE(key->key.derived.valid_chaincode);
        TEST_ASSERT_EQUAL_HEX(0x9d, key->key.derived.chaincode[0]);
        TEST_ASSERT_EQUAL_HEX(0x2d, key->key.derived.chaincode[CRYPTO_HDKEY_CHAINCODE_SIZE - 1]);
        TEST_ASSERT_EQUAL(3, key->key.derived.origin.components_count);
        TEST_ASSERT_EQUAL(path_component_type_index, key->key.derived.origin.components[0].type);
        TEST_ASSERT_TRUE(key->key.derived.origin.components[0].component.index.is_hardened);
        TEST_ASSERT_EQUAL(49, key->key.derived.origin.components[0].component.index.index);
        TEST_ASSERT_EQUAL(path_component_type_index, key->key.derived.origin.components[1].type);
        TEST_ASSERT_TRUE(key->key.derived.origin.components[1].component.index.is_hardened);
        TEST_ASSERT_EQUAL(0, key->key.derived.origin.components[1].component.index.index);
        TEST_ASSERT_EQUAL(path_component_type_index, key->key.derived.origin.components[2].type);
        TEST_ASSERT_TRUE(key->key.derived.origin.components[2].component.index.is_hardened);
        TEST_ASSERT_EQUAL(0, key->key.derived.origin.components[2].component.index.index);
        TEST_ASSERT_EQUAL(934670036, key->key.derived.origin.source_fingerprint);
        TEST_ASSERT_EQUAL(0, key->key.derived.children.components_count);
        TEST_ASSERT_EQUAL(2819587291, key->key.derived.parent_fingerprint);

        uint8_t bip32[BIP32_SERIALIZED_LEN];
        bool ok = bip32_serialize(key, bip32);
        TEST_ASSERT_TRUE(ok);
        uint8_t expected[] = {0x04, 0x88, 0xb2, 0x1e, 0x03, 0xa8, 0x0f, 0x7c, 0xdb, 0x80, 0x00, 0x00, 0x00, 0x9d, 0x2f, 0x86,
                              0x04, 0x32, 0x76, 0xf9, 0x25, 0x1a, 0x4a, 0x4f, 0x57, 0x71, 0x66, 0xa5, 0xab, 0xeb, 0x16, 0xb6,
                              0xec, 0x61, 0xe2, 0x26, 0xb5, 0xb8, 0xfa, 0x11, 0x03, 0x8b, 0xfd, 0xa4, 0x2d, 0x02, 0xc7, 0xe4,
                              0x82, 0x37, 0x30, 0xf6, 0xee, 0x2c, 0xf8, 0x64, 0xe2, 0xc3, 0x52, 0x06, 0x0a, 0x88, 0xe6, 0x0b,
                              0x51, 0xa8, 0x4e, 0x89, 0xe4, 0xc8, 0xc7, 0x5e, 0xc2, 0x25, 0x90, 0xad, 0x6b, 0x69};
        TEST_ASSERT_EQUAL_UINT8_ARRAY(expected, bip32, BIP32_SERIALIZED_LEN);

        test_format_key_origin(key, "[37b5eed4/49'/0'/0']");
        {
            char derivationpath[BUFLEN];
            int len = format_keyderivationpath(key, (char *)&derivationpath, BUFLEN);
            TEST_ASSERT_EQUAL(0, len);
        }
        {
            char *out;
            err = urc_bip32_tobase58(key, &out);
            TEST_ASSERT_EQUAL(URC_OK, err);
            const char *expected =
                "xpub6CtR1iF4dZPkEyXDwVf3HE74tSwXNMcHtBzX4gwz2UnPhJ54Jz5unHx2syYCCDkvVUmsmoYTmcaHXe1wJppvct4GMMaN5XAbRk7yGScRSte";
            TEST_ASSERT_EQUAL_STRING(expected, out);
            urc_string_free(out);
        }
    }
    {
        crypto_output *output = &account.descriptors[2];
        TEST_ASSERT_EQUAL(output_type__, output->type);
        TEST_ASSERT_EQUAL(keyexp_type_wpkh, output->output.key.type);
        TEST_ASSERT_EQUAL(keyexp_keytype_hdkey, output->output.key.keytype);
        crypto_hdkey *key = &output->output.key.key.hdkey;
        TEST_ASSERT_EQUAL(hdkey_type_derived, key->type);
        TEST_ASSERT_EQUAL_HEX(0x03, key->key.derived.keydata[0]);
        TEST_ASSERT_EQUAL_HEX(0x3f, key->key.derived.keydata[CRYPTO_HDKEY_KEYDATA_SIZE - 1]);
        TEST_ASSERT_TRUE(key->key.derived.valid_chaincode);
        TEST_ASSERT_EQUAL_HEX(0x72, key->key.derived.chaincode[0]);
        TEST_ASSERT_EQUAL_HEX(0x88, key->key.derived.chaincode[CRYPTO_HDKEY_CHAINCODE_SIZE - 1]);
        TEST_ASSERT_EQUAL(3, key->key.derived.origin.components_count);
        TEST_ASSERT_EQUAL(path_component_type_index, key->key.derived.origin.components[0].type);
        TEST_ASSERT_TRUE(key->key.derived.origin.components[0].component.index.is_hardened);
        TEST_ASSERT_EQUAL(84, key->key.derived.origin.components[0].component.index.index);
        TEST_ASSERT_EQUAL(path_component_type_index, key->key.derived.origin.components[1].type);
        TEST_ASSERT_TRUE(key->key.derived.origin.components[1].component.index.is_hardened);
        TEST_ASSERT_EQUAL(0, key->key.derived.origin.components[1].component.index.index);
        TEST_ASSERT_EQUAL(path_component_type_index, key->key.derived.origin.components[2].type);
        TEST_ASSERT_TRUE(key->key.derived.origin.components[2].component.index.is_hardened);
        TEST_ASSERT_EQUAL(0, key->key.derived.origin.components[2].component.index.index);
        TEST_ASSERT_EQUAL(934670036, key->key.derived.origin.source_fingerprint);
        TEST_ASSERT_EQUAL(0, key->key.derived.children.components_count);
        TEST_ASSERT_EQUAL(224256471, key->key.derived.parent_fingerprint);

        uint8_t bip32[BIP32_SERIALIZED_LEN];
        bool ok = bip32_serialize(key, bip32);
        TEST_ASSERT_TRUE(ok);
        uint8_t expected[] = {0x04, 0x88, 0xb2, 0x1e, 0x03, 0x0d, 0x5d, 0xe1, 0xd7, 0x80, 0x00, 0x00, 0x00, 0x72, 0xed, 0xe7,
                              0x33, 0x4d, 0x5a, 0xcf, 0x91, 0xc6, 0xfd, 0xa6, 0x22, 0xc2, 0x05, 0x19, 0x9c, 0x59, 0x5a, 0x31,
                              0xf9, 0x21, 0x8e, 0xd3, 0x07, 0x92, 0xd3, 0x01, 0xd5, 0xee, 0x9e, 0x3a, 0x88, 0x03, 0xfd, 0x43,
                              0x34, 0x50, 0xb6, 0x92, 0x4b, 0x4f, 0x7e, 0xfd, 0xd5, 0xd1, 0xed, 0x01, 0x7d, 0x36, 0x4b, 0xe9,
                              0x5a, 0xb2, 0xb5, 0x92, 0xdc, 0x8b, 0xdd, 0xb3, 0xb0, 0x0c, 0x1c, 0x24, 0xf6, 0x3f};
        TEST_ASSERT_EQUAL_UINT8_ARRAY(expected, bip32, BIP32_SERIALIZED_LEN);

        test_format_key_origin(key, "[37b5eed4/84'/0'/0']");
        {
            char derivationpath[BUFLEN];
            int len = format_keyderivationpath(key, (char *)&derivationpath, BUFLEN);
            TEST_ASSERT_EQUAL(0, len);
        }
        {
            char *out;
            err = urc_bip32_tobase58(key, &out);
            TEST_ASSERT_EQUAL(URC_OK, err);
            const char *expected =
                "xpub6BkU445MSEBXbPjD3g2c2ch6mn8yy1SXXQUM7EwjgYiq6Wt1NDwDZ45npqWcV8uQC5oi2gHuVukoCoZZyT4HKq8EpotPMqGqxdZRuapCQ23";
            TEST_ASSERT_EQUAL_STRING(expected, out);
            urc_string_free(out);
        }
    }
    {
        crypto_output *output = &account.descriptors[3];
        TEST_ASSERT_EQUAL(output_type_sh, output->type);
        TEST_ASSERT_EQUAL(keyexp_type_cosigner, output->output.key.type);
        TEST_ASSERT_EQUAL(keyexp_keytype_hdkey, output->output.key.keytype);
        crypto_hdkey *key = &output->output.key.key.hdkey;
        TEST_ASSERT_EQUAL(hdkey_type_derived, key->type);
        TEST_ASSERT_EQUAL_HEX(0x03, key->key.derived.keydata[0]);
        TEST_ASSERT_EQUAL_HEX(0x9a, key->key.derived.keydata[CRYPTO_HDKEY_KEYDATA_SIZE - 1]);
        TEST_ASSERT_TRUE(key->key.derived.valid_chaincode);
        TEST_ASSERT_EQUAL_HEX(0x88, key->key.derived.chaincode[0]);
        TEST_ASSERT_EQUAL_HEX(0x23, key->key.derived.chaincode[CRYPTO_HDKEY_CHAINCODE_SIZE - 1]);
        TEST_ASSERT_EQUAL(1, key->key.derived.origin.components_count);
        TEST_ASSERT_EQUAL(path_component_type_index, key->key.derived.origin.components[0].type);
        TEST_ASSERT_TRUE(key->key.derived.origin.components[0].component.index.is_hardened);
        TEST_ASSERT_EQUAL(45, key->key.derived.origin.components[0].component.index.index);
        TEST_ASSERT_EQUAL(934670036, key->key.derived.origin.source_fingerprint);
        TEST_ASSERT_EQUAL(0, key->key.derived.children.components_count);
        TEST_ASSERT_EQUAL(934670036, key->key.derived.parent_fingerprint);

        uint8_t bip32[BIP32_SERIALIZED_LEN];
        bool ok = bip32_serialize(key, bip32);
        TEST_ASSERT_TRUE(ok);
        uint8_t expected[] = {0x04, 0x88, 0xb2, 0x1e, 0x01, 0x37, 0xb5, 0xee, 0xd4, 0x80, 0x00, 0x00, 0x2d, 0x88, 0xd3, 0x29,
                              0x9b, 0x44, 0x8f, 0x87, 0x21, 0x5d, 0x96, 0xb0, 0xc2, 0x26, 0x23, 0x5a, 0xfc, 0x02, 0x7f, 0x9e,
                              0x7d, 0xc7, 0x00, 0x28, 0x4f, 0x3e, 0x91, 0x2a, 0x34, 0xda, 0xeb, 0x1a, 0x23, 0x03, 0x5c, 0xcd,
                              0x58, 0xb6, 0x3a, 0x2c, 0xdc, 0x23, 0xd0, 0x81, 0x27, 0x10, 0x60, 0x35, 0x92, 0xe7, 0x45, 0x75,
                              0x73, 0x21, 0x18, 0x80, 0xcb, 0x59, 0xb1, 0xef, 0x01, 0x2e, 0x16, 0x8e, 0x05, 0x9a};
        TEST_ASSERT_EQUAL_UINT8_ARRAY(expected, bip32, BIP32_SERIALIZED_LEN);

        test_format_key_origin(key, "[37b5eed4/45']");
        {
            char derivationpath[BUFLEN];
            int len = format_keyderivationpath(key, (char *)&derivationpath, BUFLEN);
            TEST_ASSERT_EQUAL(0, len);
        }
        {
            char *out;
            err = urc_bip32_tobase58(key, &out);
            TEST_ASSERT_EQUAL(URC_OK, err);
            const char *expected =
                "xpub68JFLJTH96GUqC6SoVw5c2qyLSt776PGu5xde8ddVACuPYyarvSL827TbZGavuNbKQ8DG3VP9fCXPhQRBgPrS4MPG3zaZgwAGuPHYvVuY9X";
            TEST_ASSERT_EQUAL_STRING(expected, out);
            urc_string_free(out);
        }
    }
    {
        crypto_output *output = &account.descriptors[4];
        TEST_ASSERT_EQUAL(output_type_sh_wsh, output->type);
        TEST_ASSERT_EQUAL(keyexp_type_cosigner, output->output.key.type);
        TEST_ASSERT_EQUAL(keyexp_keytype_hdkey, output->output.key.keytype);
        crypto_hdkey *key = &output->output.key.key.hdkey;
        TEST_ASSERT_EQUAL(hdkey_type_derived, key->type);
        TEST_ASSERT_EQUAL_HEX(0x03, key->key.derived.keydata[0]);
        TEST_ASSERT_EQUAL_HEX(0x11, key->key.derived.keydata[CRYPTO_HDKEY_KEYDATA_SIZE - 1]);
        TEST_ASSERT_TRUE(key->key.derived.valid_chaincode);
        TEST_ASSERT_EQUAL_HEX(0x79, key->key.derived.chaincode[0]);
        TEST_ASSERT_EQUAL_HEX(0xb6, key->key.derived.chaincode[CRYPTO_HDKEY_CHAINCODE_SIZE - 1]);
        TEST_ASSERT_EQUAL(4, key->key.derived.origin.components_count);
        TEST_ASSERT_EQUAL(path_component_type_index, key->key.derived.origin.components[0].type);
        TEST_ASSERT_TRUE(key->key.derived.origin.components[0].component.index.is_hardened);
        TEST_ASSERT_EQUAL(48, key->key.derived.origin.components[0].component.index.index);
        TEST_ASSERT_EQUAL(path_component_type_index, key->key.derived.origin.components[1].type);
        TEST_ASSERT_TRUE(key->key.derived.origin.components[1].component.index.is_hardened);
        TEST_ASSERT_EQUAL(0, key->key.derived.origin.components[1].component.index.index);
        TEST_ASSERT_EQUAL(path_component_type_index, key->key.derived.origin.components[2].type);
        TEST_ASSERT_TRUE(key->key.derived.origin.components[2].component.index.is_hardened);
        TEST_ASSERT_EQUAL(0, key->key.derived.origin.components[2].component.index.index);
        TEST_ASSERT_EQUAL(path_component_type_index, key->key.derived.origin.components[3].type);
        TEST_ASSERT_TRUE(key->key.derived.origin.components[3].component.index.is_hardened);
        TEST_ASSERT_EQUAL(1, key->key.derived.origin.components[3].component.index.index);
        TEST_ASSERT_EQUAL(934670036, key->key.derived.origin.source_fingerprint);
        TEST_ASSERT_EQUAL(0, key->key.derived.children.components_count);
        TEST_ASSERT_EQUAL(1505139498, key->key.derived.parent_fingerprint);

        uint8_t bip32[BIP32_SERIALIZED_LEN];
        bool ok = bip32_serialize(key, bip32);
        TEST_ASSERT_TRUE(ok);
        uint8_t expected[] = {0x04, 0x88, 0xb2, 0x1e, 0x04, 0x59, 0xb6, 0x9b, 0x2a, 0x80, 0x00, 0x00, 0x01, 0x79, 0x53, 0xef,
                              0xe1, 0x6a, 0x73, 0xe5, 0xd3, 0xf9, 0xf2, 0xd4, 0xc6, 0xe4, 0x9b, 0xd8, 0x8e, 0x22, 0x09, 0x3b,
                              0xbd, 0x85, 0xbe, 0x5a, 0x7e, 0x86, 0x2a, 0x4b, 0x98, 0xa1, 0x6e, 0x0a, 0xb6, 0x03, 0x2c, 0x78,
                              0xeb, 0xfc, 0xab, 0xda, 0xc6, 0xd7, 0x35, 0xa0, 0x82, 0x0e, 0xf8, 0x73, 0x2f, 0x28, 0x21, 0xb4,
                              0xfb, 0x84, 0xcd, 0x5d, 0x6b, 0x26, 0x52, 0x69, 0x38, 0xf9, 0x0c, 0x05, 0x07, 0x11};
        TEST_ASSERT_EQUAL_UINT8_ARRAY(expected, bip32, BIP32_SERIALIZED_LEN);

        test_format_key_origin(key, "[37b5eed4/48'/0'/0'/1']");
        {
            char derivationpath[BUFLEN];
            int len = format_keyderivationpath(key, (char *)&derivationpath, BUFLEN);
            TEST_ASSERT_EQUAL(0, len);
        }
        {
            char *out;
            err = urc_bip32_tobase58(key, &out);
            TEST_ASSERT_EQUAL(URC_OK, err);
            const char *expected =
                "xpub6EC9f7mLFJQoPaqDJ72Zbv67JWzmpXvCYQSecER9GzkYy5eWLsVLbHnxoAZ8NnnsrjhMLduJo9dG6fNQkmMFL3Qedj2kf5bEy5tptHPApNf";
            TEST_ASSERT_EQUAL_STRING(expected, out);
            urc_string_free(out);
        }
    }
    {
        crypto_output *output = &account.descriptors[5];
        TEST_ASSERT_EQUAL(output_type_wsh, output->type);
        TEST_ASSERT_EQUAL(keyexp_type_cosigner, output->output.key.type);
        TEST_ASSERT_EQUAL(keyexp_keytype_hdkey, output->output.key.keytype);
        crypto_hdkey *key = &output->output.key.key.hdkey;
        TEST_ASSERT_EQUAL(hdkey_type_derived, key->type);
        TEST_ASSERT_EQUAL_HEX(0x02, key->key.derived.keydata[0]);
        TEST_ASSERT_EQUAL_HEX(0x46, key->key.derived.keydata[CRYPTO_HDKEY_KEYDATA_SIZE - 1]);
        TEST_ASSERT_TRUE(key->key.derived.valid_chaincode);
        TEST_ASSERT_EQUAL_HEX(0x2f, key->key.derived.chaincode[0]);
        TEST_ASSERT_EQUAL_HEX(0x13, key->key.derived.chaincode[CRYPTO_HDKEY_CHAINCODE_SIZE - 1]);
        TEST_ASSERT_EQUAL(4, key->key.derived.origin.components_count);
        TEST_ASSERT_EQUAL(path_component_type_index, key->key.derived.origin.components[0].type);
        TEST_ASSERT_TRUE(key->key.derived.origin.components[0].component.index.is_hardened);
        TEST_ASSERT_EQUAL(48, key->key.derived.origin.components[0].component.index.index);
        TEST_ASSERT_EQUAL(path_component_type_index, key->key.derived.origin.components[1].type);
        TEST_ASSERT_TRUE(key->key.derived.origin.components[1].component.index.is_hardened);
        TEST_ASSERT_EQUAL(0, key->key.derived.origin.components[1].component.index.index);
        TEST_ASSERT_EQUAL(path_component_type_index, key->key.derived.origin.components[2].type);
        TEST_ASSERT_TRUE(key->key.derived.origin.components[2].component.index.is_hardened);
        TEST_ASSERT_EQUAL(0, key->key.derived.origin.components[2].component.index.index);
        TEST_ASSERT_EQUAL(path_component_type_index, key->key.derived.origin.components[3].type);
        TEST_ASSERT_TRUE(key->key.derived.origin.components[3].component.index.is_hardened);
        TEST_ASSERT_EQUAL(2, key->key.derived.origin.components[3].component.index.index);
        TEST_ASSERT_EQUAL(934670036, key->key.derived.origin.source_fingerprint);
        TEST_ASSERT_EQUAL(0, key->key.derived.children.components_count);
        TEST_ASSERT_EQUAL(1505139498, key->key.derived.parent_fingerprint);

        uint8_t bip32[BIP32_SERIALIZED_LEN];
        bool ok = bip32_serialize(key, bip32);
        TEST_ASSERT_TRUE(ok);
        uint8_t expected[] = {0x04, 0x88, 0xb2, 0x1e, 0x04, 0x59, 0xb6, 0x9b, 0x2a, 0x80, 0x00, 0x00, 0x02, 0x2f, 0xa0, 0xe4,
                              0x1c, 0x9d, 0xc4, 0x3d, 0xc4, 0x51, 0x86, 0x59, 0xbf, 0xce, 0xf9, 0x35, 0xba, 0x81, 0x01, 0xb5,
                              0x7d, 0xbc, 0x08, 0x12, 0x80, 0x5d, 0xd9, 0x83, 0xbc, 0x1d, 0x34, 0xb8, 0x13, 0x02, 0x60, 0x56,
                              0x3e, 0xe8, 0x0c, 0x26, 0x84, 0x46, 0x21, 0xb0, 0x6b, 0x74, 0x07, 0x0b, 0xaf, 0x0e, 0x23, 0xfb,
                              0x76, 0xce, 0x43, 0x9d, 0x02, 0x37, 0xe8, 0x75, 0x02, 0xeb, 0xbd, 0x3c, 0xa3, 0x46};
        TEST_ASSERT_EQUAL_UINT8_ARRAY(expected, bip32, BIP32_SERIALIZED_LEN);

        test_format_key_origin(key, "[37b5eed4/48'/0'/0'/2']");
        {
            char derivationpath[BUFLEN];
            int len = format_keyderivationpath(key, (char *)&derivationpath, BUFLEN);
            TEST_ASSERT_EQUAL(0, len);
        }
        {
            char *out;
            err = urc_bip32_tobase58(key, &out);
            TEST_ASSERT_EQUAL(URC_OK, err);
            const char *expected =
                "xpub6EC9f7mLFJQoRQ6qiTvWQeeYsgtki6fBzSUgWgUtAujEMtAfJSAn3AVS4KrLHRV2hNX77YwNkg4azUzuSwhNGtcq4r2J8bLGMDkrQYHvoed";
            TEST_ASSERT_EQUAL_STRING(expected, out);
            urc_string_free(out);
        }
    }
}

TEST(parser, crypto_jadeaccount_parse)
{
    // https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2020-015-account.md#exampletest-vector
    const char *hex =
        "a2011ab6215d6b0281d90194d9012fa4035821025d6aca89f721020f672d1653f87d171c1ad4103a24e8eaa3a07c596bc6652f7a045820e6b977baf5"
        "cd1a24eedb65292c78b4680f658ab11aeff1671d5246f71636860b06d90130a301861854f500f500f5021ab6215d6b0303081a97538da9";
    uint8_t raw[BUFLEN];
    size_t len = h2b(hex, BUFLEN, (uint8_t *)(&raw));
    TEST_ASSERT_GREATER_THAN_INT(0, len);

    crypto_account account;
    int err = urc_jade_account_parse(raw, len, &account);
    TEST_ASSERT_EQUAL(URC_OK, err);

    TEST_ASSERT_EQUAL(3055639915, account.master_fingerprint);
    TEST_ASSERT_EQUAL(1, account.descriptors_count);
    crypto_output *output = &account.descriptors[0];
    TEST_ASSERT_EQUAL(output_type__, output->type);
    TEST_ASSERT_EQUAL(keyexp_type_wpkh, output->output.key.type);
    TEST_ASSERT_EQUAL(keyexp_keytype_hdkey, output->output.key.keytype);
    crypto_hdkey *key = &output->output.key.key.hdkey;
    TEST_ASSERT_EQUAL(hdkey_type_derived, key->type);
    TEST_ASSERT_EQUAL_HEX(0x02, key->key.derived.keydata[0]);
    TEST_ASSERT_EQUAL_HEX(0x7a, key->key.derived.keydata[CRYPTO_HDKEY_KEYDATA_SIZE - 1]);
    TEST_ASSERT_EQUAL_HEX(0xe6, key->key.derived.chaincode[0]);
    TEST_ASSERT_EQUAL_HEX(0x0b, key->key.derived.chaincode[CRYPTO_HDKEY_CHAINCODE_SIZE - 1]);
    TEST_ASSERT_EQUAL(2538835369, key->key.derived.parent_fingerprint);
    TEST_ASSERT_EQUAL(3055639915, key->key.derived.origin.source_fingerprint);
    TEST_ASSERT_EQUAL(3, key->key.derived.origin.depth);
    TEST_ASSERT_EQUAL(3, key->key.derived.origin.components_count);
    TEST_ASSERT_EQUAL(path_component_type_index, key->key.derived.origin.components[0].type);
    TEST_ASSERT_EQUAL(84, key->key.derived.origin.components[0].component.index.index);
    TEST_ASSERT_TRUE(key->key.derived.origin.components[0].component.index.is_hardened);
    TEST_ASSERT_EQUAL(path_component_type_index, key->key.derived.origin.components[1].type);
    TEST_ASSERT_EQUAL(0, key->key.derived.origin.components[1].component.index.index);
    TEST_ASSERT_TRUE(key->key.derived.origin.components[1].component.index.is_hardened);
    TEST_ASSERT_EQUAL(path_component_type_index, key->key.derived.origin.components[2].type);
    TEST_ASSERT_EQUAL(0, key->key.derived.origin.components[2].component.index.index);
    TEST_ASSERT_TRUE(key->key.derived.origin.components[2].component.index.is_hardened);

    test_format_key_origin(key, "[b6215d6b/84'/0'/0']");
    {
        char derivationpath[BUFLEN];
        int len = format_keyderivationpath(key, (char *)&derivationpath, BUFLEN);
        TEST_ASSERT_EQUAL(0, len);
    }
    {
        char *out;
        err = urc_bip32_tobase58(key, &out);
        TEST_ASSERT_EQUAL(URC_OK, err);
        const char *expected =
            "xpub6CmHFAns2t9zT1HUC5YFEjzcNiwUdQEiez6o2NvVSRvrk5nC3s8mwW57GvPNCEJ2tQTpVa21Gyu4GJgUPfT3NgahVcsTiNCQnMXXTkpq5Ld";
        TEST_ASSERT_EQUAL_STRING(expected, out);
        urc_string_free(out);
    }
}

TEST(parser, jaderesponse_parse)
{
    const char *hex =
        "a2667075626b657958210252835e60d6157695c0faf7ab501c1ef206332652f47a4a69d09a388632b2428369656e6372797074656458606ebdd102c0"
        "24adbd2a26140262a31d1948863df0d6fc21b6a249028f5c97e3b553d79417310931ba8d6467d4a3e0f64a77999300708f19c9fc4ea5f2b13e0ebb17"
        "9137e6b192bf711fb364857912364a62f02f59c3723d0072c42b59b9a14f34"
        "cd1a24eedb65292c78b4680f658ab11aeff1671d5246f71636860b06d90130a301861854f500f500f5021ab6215d6b0303081a97538da9";
    uint8_t raw[BUFLEN];
    size_t len = h2b(hex, BUFLEN, (uint8_t *)(&raw));
    TEST_ASSERT_GREATER_THAN_INT(0, len);

    jade_bip8539_response response;
    uint8_t *out;

    int err = urc_jade_bip8539_response_parse(raw, len, &response);
    TEST_ASSERT_EQUAL(URC_OK, err);

    TEST_ASSERT_EQUAL_HEX(0x02, response.pubkey[0]);
    TEST_ASSERT_EQUAL_HEX(0x83, response.pubkey[CRYPTO_ECKEY_PUBLIC_COMPRESSED_SIZE - 1]);

    TEST_ASSERT_EQUAL(96, response.encrypted_len);
    TEST_ASSERT_EQUAL_HEX(0x6e, response.encrypted_data[0]);
    TEST_ASSERT_EQUAL_HEX(0x34, response.encrypted_data[response.encrypted_len - 1]);

    urc_jade_bip8539_response_free(&response);
}
