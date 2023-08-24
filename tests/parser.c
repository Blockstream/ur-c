
#include "unity.h"

#include "ur-c/crypto_account.h"
#include "ur-c/crypto_hdkey.h"
#include "ur-c/crypto_output.h"
#include "ur-c/error.h"
#include "ur-c/urc.h"

#include "helpers.h"

#define BUFSIZE 1000

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
    TEST_ASSERT_EQUAL_HEX(0xc7, seed.seed[0]);
    TEST_ASSERT_EQUAL_HEX(0x52, seed.seed[CRYPTO_SEED_SIZE - 1]);
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
    TEST_ASSERT_EQUAL_HEX(0x70, psbt.buffer[0]);
    TEST_ASSERT_EQUAL_HEX(0x00, psbt.buffer[psbt.psbt_len - 1]);
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
    TEST_ASSERT_EQUAL_HEX(0x8c, eckey.key.private[0]);
    TEST_ASSERT_EQUAL_HEX(0xaa, eckey.key.private[CRYPTO_ECKEY_PRIVATE_SIZE - 1]);
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
    TEST_ASSERT_EQUAL_HEX(0x00, hdkey.key.master.keydata[0]);
    TEST_ASSERT_EQUAL_HEX(0x35, hdkey.key.master.keydata[CRYPTO_HDKEY_KEYDATA_SIZE - 1]);
    TEST_ASSERT_EQUAL_HEX(0x87, hdkey.key.master.chaincode[0]);
    TEST_ASSERT_EQUAL_HEX(0x08, hdkey.key.master.chaincode[CRYPTO_HDKEY_CHAINCODE_SIZE - 1]);
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

    TEST_ASSERT_EQUAL_HEX(0x02, hdkey.key.derived.keydata[0]);
    TEST_ASSERT_EQUAL_HEX(0xa6, hdkey.key.derived.keydata[CRYPTO_HDKEY_KEYDATA_SIZE - 1]);

    TEST_ASSERT_TRUE(hdkey.key.derived.valid_chaincode);
    TEST_ASSERT_EQUAL_HEX(0xce, hdkey.key.derived.chaincode[0]);
    TEST_ASSERT_EQUAL_HEX(0x85, hdkey.key.derived.chaincode[CRYPTO_HDKEY_CHAINCODE_SIZE - 1]);

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

void test_crypto_output_parse_1() {
    // https://github.com/BlockchainCommons/Research/blob/master/papers/urc-2020-010-output-desc.md#exampletest-vector-1
    const char *hex = "d90193d90132a103582102c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";
    uint8_t raw[BUFSIZE];
    int len = h2b(hex, BUFSIZE, (uint8_t *)(&raw));
    TEST_ASSERT_GREATER_THAN_INT(0, len);

    crypto_output output;
    urc_error err = parse_output(len, raw, &output);
    TEST_ASSERT_EQUAL(urc_error_tag_noerror, err.tag);
    TEST_ASSERT_EQUAL(output_type__, output.type);
    TEST_ASSERT_EQUAL(keyexp_keytype_eckey, output.output.key.keytype);
    TEST_ASSERT_EQUAL(eckey_type_public_compressed, output.output.key.key.eckey.type);
    TEST_ASSERT_EQUAL_HEX(0x02, output.output.key.key.eckey.key.public_compressed[0]);
    TEST_ASSERT_EQUAL_HEX(0xe5, output.output.key.key.eckey.key.public_compressed[CRYPTO_ECKEY_PUBLIC_COMPRESSED_SIZE - 1]);
}

void test_crypto_output_parse_2() {
    // https://github.com/BlockchainCommons/Research/blob/master/papers/urc-2020-010-output-desc.md#exampletest-vector-1
    const char *hex = "d90190d90194d90132a103582103fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556";
    uint8_t raw[BUFSIZE];
    int len = h2b(hex, BUFSIZE, (uint8_t *)(&raw));
    TEST_ASSERT_GREATER_THAN_INT(0, len);

    crypto_output output;
    urc_error err = parse_output(len, raw, &output);
    TEST_ASSERT_EQUAL(urc_error_tag_noerror, err.tag);
    TEST_ASSERT_EQUAL(output_type_sh, output.type);
    TEST_ASSERT_EQUAL(keyexp_type_wpkh, output.output.key.type);
    TEST_ASSERT_EQUAL(keyexp_keytype_eckey, output.output.key.keytype);
    TEST_ASSERT_EQUAL(eckey_type_public_compressed, output.output.key.key.eckey.type);
    TEST_ASSERT_EQUAL_HEX(0x03, output.output.key.key.eckey.key.public_compressed[0]);
    TEST_ASSERT_EQUAL(
        0x56, output.output.key.key.eckey.key.public_compressed[CRYPTO_ECKEY_PUBLIC_COMPRESSED_SIZE - 1]);
}

void test_crypto_output_parse_3() {
    // https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2020-010-output-desc.md#exampletest-vector-3
    const char *hex = "d90190d90196a201020282d90132a1035821022f01e5e15cca351daff3843fb70f3c2f0a1bdd05e5af888a67784ef3e10a2a01d901"
                      "32a103582103acd484e2f0c7f65309ad178a9f559abde09796974c57e714c35f110dfc27ccbe";
    uint8_t raw[BUFSIZE];
    int len = h2b(hex, BUFSIZE, (uint8_t *)(&raw));
    TEST_ASSERT_GREATER_THAN_INT(0, len);

    crypto_output output;
    urc_error err = parse_output(len, raw, &output);
    TEST_ASSERT_EQUAL(urc_error_tag_unhandledcase, err.tag);
}

void test_crypto_output_parse_4() {
    // https://github.com/BlockchainCommons/Research/blob/master/papers/urc-2020-010-output-desc.md#exampletest-vector-4
    const char *hex =
        "d90193d9012fa503582102d2b36900396c9282fa14628566582f206a5dd0bcc8d5e892611806cafb0301f0045820637807030d55d01f9a0cb3a78395"
        "15d796bd07706386a6eddf06cc29a65a0e2906d90130a30186182cf500f500f5021ad34db33f030407d90130a1018401f480f4081a78412e3a";
    uint8_t raw[BUFSIZE];
    int len = h2b(hex, BUFSIZE, (uint8_t *)(&raw));
    TEST_ASSERT_GREATER_THAN_INT(0, len);

    crypto_output output;
    urc_error err = parse_output(len, raw, &output);
    TEST_ASSERT_EQUAL(urc_error_tag_noerror, err.tag);
    TEST_ASSERT_EQUAL(output_type__, output.type);
    TEST_ASSERT_EQUAL(keyexp_type_pkh, output.output.key.type);
    TEST_ASSERT_EQUAL(keyexp_keytype_hdkey, output.output.key.keytype);
    TEST_ASSERT_EQUAL(hdkey_type_derived, output.output.key.key.hdkey.type);
    TEST_ASSERT_EQUAL_HEX(0x02, output.output.key.key.hdkey.key.derived.keydata[0]);
    TEST_ASSERT_EQUAL_HEX(0xf0, output.output.key.key.hdkey.key.derived.keydata[CRYPTO_HDKEY_KEYDATA_SIZE - 1]);

    TEST_ASSERT_TRUE(output.output.key.key.hdkey.key.derived.valid_chaincode);
    TEST_ASSERT_EQUAL_HEX(0x63, output.output.key.key.hdkey.key.derived.chaincode[0]);
    TEST_ASSERT_EQUAL_HEX(0x29, output.output.key.key.hdkey.key.derived.chaincode[CRYPTO_HDKEY_CHAINCODE_SIZE - 1]);
    //
    TEST_ASSERT_TRUE(output.output.key.key.hdkey.key.derived.valid_origin);
    TEST_ASSERT_EQUAL(3, output.output.key.key.hdkey.key.derived.origin.components_count);
    //
    TEST_ASSERT_EQUAL(path_component_type_index, output.output.key.key.hdkey.key.derived.origin.components[0].type);
    TEST_ASSERT_TRUE(output.output.key.key.hdkey.key.derived.origin.components[0].component.index.is_hardened);
    TEST_ASSERT_EQUAL(44, output.output.key.key.hdkey.key.derived.origin.components[0].component.index.index);

    TEST_ASSERT_EQUAL(path_component_type_index, output.output.key.key.hdkey.key.derived.origin.components[1].type);
    TEST_ASSERT_TRUE(output.output.key.key.hdkey.key.derived.origin.components[1].component.index.is_hardened);
    TEST_ASSERT_EQUAL(0, output.output.key.key.hdkey.key.derived.origin.components[1].component.index.index);

    TEST_ASSERT_EQUAL(path_component_type_index, output.output.key.key.hdkey.key.derived.origin.components[2].type);
    TEST_ASSERT_TRUE(output.output.key.key.hdkey.key.derived.origin.components[2].component.index.is_hardened);
    TEST_ASSERT_EQUAL(0, output.output.key.key.hdkey.key.derived.origin.components[2].component.index.index);

    TEST_ASSERT_TRUE(output.output.key.key.hdkey.key.derived.valid_children);
    TEST_ASSERT_EQUAL(2, output.output.key.key.hdkey.key.derived.children.components_count);

    TEST_ASSERT_EQUAL(path_component_type_index, output.output.key.key.hdkey.key.derived.children.components[0].type);
    TEST_ASSERT_FALSE(output.output.key.key.hdkey.key.derived.children.components[0].component.index.is_hardened);
    TEST_ASSERT_EQUAL(1, output.output.key.key.hdkey.key.derived.children.components[0].component.index.index);

    TEST_ASSERT_EQUAL(path_component_type_wildcard, output.output.key.key.hdkey.key.derived.children.components[1].type);
    TEST_ASSERT_FALSE(output.output.key.key.hdkey.key.derived.children.components[1].component.wildcard.is_hardened);

    TEST_ASSERT_EQUAL(2017537594, output.output.key.key.hdkey.key.derived.parent_fingerprint);
}

void test_crypto_output_parse_5() {
    // https://github.com/BlockchainCommons/Research/blob/master/papers/urc-2020-010-output-desc.md#exampletest-vector-5
    const char *hex = "d90191d90196a201010282d9012fa403582103cbcaa9c98c877a26977d00825c956a238e8dddfbd322cce4f74b0b5bd6ace4a70458"
                      "2060499f801b896d83179a4374aeb7822aaeaceaa0db1f85ee3e904c4defbd968906d90130a20180030007d90130a1018601f400f4"
                      "80f4d9012fa403582102fc9e5af0ac8d9b3cecfe2a888e2117ba3d089d8585886c9c826b6b22a98d12ea045820f0909affaa7ee7ab"
                      "e5dd4e100598d4dc53cd709d5a5c2cac40e7412f232f7c9c06d90130a2018200f4021abd16bee507d90130a1018600f400f480f4";
    uint8_t raw[BUFSIZE];
    int len = h2b(hex, BUFSIZE, (uint8_t *)(&raw));
    TEST_ASSERT_GREATER_THAN_INT(0, len);

    crypto_output output;
    urc_error err = parse_output(len, raw, &output);
    TEST_ASSERT_EQUAL(urc_error_tag_unhandledcase, err.tag);
}

void test_crypto_account_parse() {
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
    uint8_t raw[BUFSIZE];
    int len = h2b(hex, BUFSIZE, (uint8_t *)(&raw));
    TEST_ASSERT_GREATER_THAN_INT(0, len);

    crypto_account account;
    urc_error err = parse_account(len, raw, &account);
    TEST_ASSERT_EQUAL(urc_error_tag_taprootnotsupported, err.tag);

    TEST_ASSERT_EQUAL(934670036, account.master_fingerprint);
    TEST_ASSERT_EQUAL(6, account.descriptors_count);

    {
        crypto_output output = account.descriptors[0];
        TEST_ASSERT_EQUAL(output_type__, output.type);
        TEST_ASSERT_EQUAL(keyexp_type_pkh, output.output.key.type);
        TEST_ASSERT_EQUAL(keyexp_keytype_hdkey, output.output.key.keytype);
        TEST_ASSERT_EQUAL(hdkey_type_derived, output.output.key.key.hdkey.type);
        TEST_ASSERT_EQUAL_HEX(0x03, output.output.key.key.hdkey.key.derived.keydata[0]);
        TEST_ASSERT_EQUAL_HEX(0x32, output.output.key.key.hdkey.key.derived.keydata[CRYPTO_HDKEY_KEYDATA_SIZE - 1]);
        TEST_ASSERT_TRUE(output.output.key.key.hdkey.key.derived.valid_chaincode);
        TEST_ASSERT_EQUAL_HEX(0x64, output.output.key.key.hdkey.key.derived.chaincode[0]);
        TEST_ASSERT_EQUAL_HEX(0x5b, output.output.key.key.hdkey.key.derived.chaincode[CRYPTO_HDKEY_CHAINCODE_SIZE - 1]);
        TEST_ASSERT_TRUE(output.output.key.key.hdkey.key.derived.valid_origin);
        TEST_ASSERT_EQUAL(3, output.output.key.key.hdkey.key.derived.origin.components_count);
        TEST_ASSERT_EQUAL(path_component_type_index, output.output.key.key.hdkey.key.derived.origin.components[0].type);
        TEST_ASSERT_TRUE(output.output.key.key.hdkey.key.derived.origin.components[0].component.index.is_hardened);
        TEST_ASSERT_EQUAL(44, output.output.key.key.hdkey.key.derived.origin.components[0].component.index.index);
        TEST_ASSERT_EQUAL(path_component_type_index, output.output.key.key.hdkey.key.derived.origin.components[1].type);
        TEST_ASSERT_TRUE(output.output.key.key.hdkey.key.derived.origin.components[1].component.index.is_hardened);
        TEST_ASSERT_EQUAL(0, output.output.key.key.hdkey.key.derived.origin.components[1].component.index.index);
        TEST_ASSERT_EQUAL(path_component_type_index, output.output.key.key.hdkey.key.derived.origin.components[2].type);
        TEST_ASSERT_TRUE(output.output.key.key.hdkey.key.derived.origin.components[2].component.index.is_hardened);
        TEST_ASSERT_EQUAL(0, output.output.key.key.hdkey.key.derived.origin.components[2].component.index.index);
        TEST_ASSERT_EQUAL(934670036, output.output.key.key.hdkey.key.derived.origin.source_fingerprint);
        TEST_ASSERT_FALSE(output.output.key.key.hdkey.key.derived.valid_children);
        TEST_ASSERT_EQUAL(2583285239, output.output.key.key.hdkey.key.derived.parent_fingerprint);
    }
    {
        crypto_output output = account.descriptors[1];
        TEST_ASSERT_EQUAL(output_type_sh, output.type);
        TEST_ASSERT_EQUAL(keyexp_type_wpkh, output.output.key.type);
        TEST_ASSERT_EQUAL(keyexp_keytype_hdkey, output.output.key.keytype);
        TEST_ASSERT_EQUAL(hdkey_type_derived, output.output.key.key.hdkey.type);
        TEST_ASSERT_EQUAL_HEX(0x02, output.output.key.key.hdkey.key.derived.keydata[0]);
        TEST_ASSERT_EQUAL_HEX(0x69, output.output.key.key.hdkey.key.derived.keydata[CRYPTO_HDKEY_KEYDATA_SIZE - 1]);
        TEST_ASSERT_TRUE(output.output.key.key.hdkey.key.derived.valid_chaincode);
        TEST_ASSERT_EQUAL_HEX(0x9d, output.output.key.key.hdkey.key.derived.chaincode[0]);
        TEST_ASSERT_EQUAL_HEX(0x2d, output.output.key.key.hdkey.key.derived.chaincode[CRYPTO_HDKEY_CHAINCODE_SIZE - 1]);
        TEST_ASSERT_TRUE(output.output.key.key.hdkey.key.derived.valid_origin);
        TEST_ASSERT_EQUAL(3, output.output.key.key.hdkey.key.derived.origin.components_count);
        TEST_ASSERT_EQUAL(path_component_type_index, output.output.key.key.hdkey.key.derived.origin.components[0].type);
        TEST_ASSERT_TRUE(output.output.key.key.hdkey.key.derived.origin.components[0].component.index.is_hardened);
        TEST_ASSERT_EQUAL(49, output.output.key.key.hdkey.key.derived.origin.components[0].component.index.index);
        TEST_ASSERT_EQUAL(path_component_type_index, output.output.key.key.hdkey.key.derived.origin.components[1].type);
        TEST_ASSERT_TRUE(output.output.key.key.hdkey.key.derived.origin.components[1].component.index.is_hardened);
        TEST_ASSERT_EQUAL(0, output.output.key.key.hdkey.key.derived.origin.components[1].component.index.index);
        TEST_ASSERT_EQUAL(path_component_type_index, output.output.key.key.hdkey.key.derived.origin.components[2].type);
        TEST_ASSERT_TRUE(output.output.key.key.hdkey.key.derived.origin.components[2].component.index.is_hardened);
        TEST_ASSERT_EQUAL(0, output.output.key.key.hdkey.key.derived.origin.components[2].component.index.index);
        TEST_ASSERT_EQUAL(934670036, output.output.key.key.hdkey.key.derived.origin.source_fingerprint);
        TEST_ASSERT_FALSE(output.output.key.key.hdkey.key.derived.valid_children);
        TEST_ASSERT_EQUAL(2819587291, output.output.key.key.hdkey.key.derived.parent_fingerprint);
    }
    {
        crypto_output output = account.descriptors[2];
        TEST_ASSERT_EQUAL(output_type__, output.type);
        TEST_ASSERT_EQUAL(keyexp_type_wpkh, output.output.key.type);
        TEST_ASSERT_EQUAL(keyexp_keytype_hdkey, output.output.key.keytype);
        TEST_ASSERT_EQUAL(hdkey_type_derived, output.output.key.key.hdkey.type);
        TEST_ASSERT_EQUAL_HEX(0x03, output.output.key.key.hdkey.key.derived.keydata[0]);
        TEST_ASSERT_EQUAL_HEX(0x3f, output.output.key.key.hdkey.key.derived.keydata[CRYPTO_HDKEY_KEYDATA_SIZE - 1]);
        TEST_ASSERT_TRUE(output.output.key.key.hdkey.key.derived.valid_chaincode);
        TEST_ASSERT_EQUAL_HEX(0x72, output.output.key.key.hdkey.key.derived.chaincode[0]);
        TEST_ASSERT_EQUAL_HEX(0x88, output.output.key.key.hdkey.key.derived.chaincode[CRYPTO_HDKEY_CHAINCODE_SIZE - 1]);
        TEST_ASSERT_TRUE(output.output.key.key.hdkey.key.derived.valid_origin);
        TEST_ASSERT_EQUAL(3, output.output.key.key.hdkey.key.derived.origin.components_count);
        TEST_ASSERT_EQUAL(path_component_type_index, output.output.key.key.hdkey.key.derived.origin.components[0].type);
        TEST_ASSERT_TRUE(output.output.key.key.hdkey.key.derived.origin.components[0].component.index.is_hardened);
        TEST_ASSERT_EQUAL(84, output.output.key.key.hdkey.key.derived.origin.components[0].component.index.index);
        TEST_ASSERT_EQUAL(path_component_type_index, output.output.key.key.hdkey.key.derived.origin.components[1].type);
        TEST_ASSERT_TRUE(output.output.key.key.hdkey.key.derived.origin.components[1].component.index.is_hardened);
        TEST_ASSERT_EQUAL(0, output.output.key.key.hdkey.key.derived.origin.components[1].component.index.index);
        TEST_ASSERT_EQUAL(path_component_type_index, output.output.key.key.hdkey.key.derived.origin.components[2].type);
        TEST_ASSERT_TRUE(output.output.key.key.hdkey.key.derived.origin.components[2].component.index.is_hardened);
        TEST_ASSERT_EQUAL(0, output.output.key.key.hdkey.key.derived.origin.components[2].component.index.index);
        TEST_ASSERT_EQUAL(934670036, output.output.key.key.hdkey.key.derived.origin.source_fingerprint);
        TEST_ASSERT_FALSE(output.output.key.key.hdkey.key.derived.valid_children);
        TEST_ASSERT_EQUAL(224256471, output.output.key.key.hdkey.key.derived.parent_fingerprint);
    }
    {
        crypto_output output = account.descriptors[3];
        TEST_ASSERT_EQUAL(output_type_sh, output.type);
        TEST_ASSERT_EQUAL(keyexp_type_cosigner, output.output.key.type);
        TEST_ASSERT_EQUAL(keyexp_keytype_hdkey, output.output.key.keytype);
        TEST_ASSERT_EQUAL(hdkey_type_derived, output.output.key.key.hdkey.type);
        TEST_ASSERT_EQUAL_HEX(0x03, output.output.key.key.hdkey.key.derived.keydata[0]);
        TEST_ASSERT_EQUAL_HEX(0x9a, output.output.key.key.hdkey.key.derived.keydata[CRYPTO_HDKEY_KEYDATA_SIZE - 1]);
        TEST_ASSERT_TRUE(output.output.key.key.hdkey.key.derived.valid_chaincode);
        TEST_ASSERT_EQUAL_HEX(0x88, output.output.key.key.hdkey.key.derived.chaincode[0]);
        TEST_ASSERT_EQUAL_HEX(0x23, output.output.key.key.hdkey.key.derived.chaincode[CRYPTO_HDKEY_CHAINCODE_SIZE - 1]);
        TEST_ASSERT_TRUE(output.output.key.key.hdkey.key.derived.valid_origin);
        TEST_ASSERT_EQUAL(1, output.output.key.key.hdkey.key.derived.origin.components_count);
        TEST_ASSERT_EQUAL(path_component_type_index, output.output.key.key.hdkey.key.derived.origin.components[0].type);
        TEST_ASSERT_TRUE(output.output.key.key.hdkey.key.derived.origin.components[0].component.index.is_hardened);
        TEST_ASSERT_EQUAL(45, output.output.key.key.hdkey.key.derived.origin.components[0].component.index.index);
        TEST_ASSERT_EQUAL(934670036, output.output.key.key.hdkey.key.derived.origin.source_fingerprint);
        TEST_ASSERT_FALSE(output.output.key.key.hdkey.key.derived.valid_children);
        TEST_ASSERT_EQUAL(934670036, output.output.key.key.hdkey.key.derived.parent_fingerprint);
    }
    {
        crypto_output output = account.descriptors[4];
        TEST_ASSERT_EQUAL(output_type_sh_wsh, output.type);
        TEST_ASSERT_EQUAL(keyexp_type_cosigner, output.output.key.type);
        TEST_ASSERT_EQUAL(keyexp_keytype_hdkey, output.output.key.keytype);
        TEST_ASSERT_EQUAL(hdkey_type_derived, output.output.key.key.hdkey.type);
        TEST_ASSERT_EQUAL_HEX(0x03, output.output.key.key.hdkey.key.derived.keydata[0]);
        TEST_ASSERT_EQUAL_HEX(0x11, output.output.key.key.hdkey.key.derived.keydata[CRYPTO_HDKEY_KEYDATA_SIZE - 1]);
        TEST_ASSERT_TRUE(output.output.key.key.hdkey.key.derived.valid_chaincode);
        TEST_ASSERT_EQUAL_HEX(0x79, output.output.key.key.hdkey.key.derived.chaincode[0]);
        TEST_ASSERT_EQUAL_HEX(0xb6, output.output.key.key.hdkey.key.derived.chaincode[CRYPTO_HDKEY_CHAINCODE_SIZE - 1]);
        TEST_ASSERT_TRUE(output.output.key.key.hdkey.key.derived.valid_origin);
        TEST_ASSERT_EQUAL(4, output.output.key.key.hdkey.key.derived.origin.components_count);
        TEST_ASSERT_EQUAL(path_component_type_index, output.output.key.key.hdkey.key.derived.origin.components[0].type);
        TEST_ASSERT_TRUE(output.output.key.key.hdkey.key.derived.origin.components[0].component.index.is_hardened);
        TEST_ASSERT_EQUAL(48, output.output.key.key.hdkey.key.derived.origin.components[0].component.index.index);
        TEST_ASSERT_EQUAL(path_component_type_index, output.output.key.key.hdkey.key.derived.origin.components[1].type);
        TEST_ASSERT_TRUE(output.output.key.key.hdkey.key.derived.origin.components[1].component.index.is_hardened);
        TEST_ASSERT_EQUAL(0, output.output.key.key.hdkey.key.derived.origin.components[1].component.index.index);
        TEST_ASSERT_EQUAL(path_component_type_index, output.output.key.key.hdkey.key.derived.origin.components[2].type);
        TEST_ASSERT_TRUE(output.output.key.key.hdkey.key.derived.origin.components[2].component.index.is_hardened);
        TEST_ASSERT_EQUAL(0, output.output.key.key.hdkey.key.derived.origin.components[2].component.index.index);
        TEST_ASSERT_EQUAL(path_component_type_index, output.output.key.key.hdkey.key.derived.origin.components[3].type);
        TEST_ASSERT_TRUE(output.output.key.key.hdkey.key.derived.origin.components[3].component.index.is_hardened);
        TEST_ASSERT_EQUAL(1, output.output.key.key.hdkey.key.derived.origin.components[3].component.index.index);
        TEST_ASSERT_EQUAL(934670036, output.output.key.key.hdkey.key.derived.origin.source_fingerprint);
        TEST_ASSERT_FALSE(output.output.key.key.hdkey.key.derived.valid_children);
        TEST_ASSERT_EQUAL(1505139498, output.output.key.key.hdkey.key.derived.parent_fingerprint);
    }
    {
        crypto_output output = account.descriptors[5];
        TEST_ASSERT_EQUAL(output_type_wsh, output.type);
        TEST_ASSERT_EQUAL(keyexp_type_cosigner, output.output.key.type);
        TEST_ASSERT_EQUAL(keyexp_keytype_hdkey, output.output.key.keytype);
        TEST_ASSERT_EQUAL(hdkey_type_derived, output.output.key.key.hdkey.type);
        TEST_ASSERT_EQUAL_HEX(0x02, output.output.key.key.hdkey.key.derived.keydata[0]);
        TEST_ASSERT_EQUAL_HEX(0x46, output.output.key.key.hdkey.key.derived.keydata[CRYPTO_HDKEY_KEYDATA_SIZE - 1]);
        TEST_ASSERT_TRUE(output.output.key.key.hdkey.key.derived.valid_chaincode);
        TEST_ASSERT_EQUAL_HEX(0x2f, output.output.key.key.hdkey.key.derived.chaincode[0]);
        TEST_ASSERT_EQUAL_HEX(0x13, output.output.key.key.hdkey.key.derived.chaincode[CRYPTO_HDKEY_CHAINCODE_SIZE - 1]);
        TEST_ASSERT_TRUE(output.output.key.key.hdkey.key.derived.valid_origin);
        TEST_ASSERT_EQUAL(4, output.output.key.key.hdkey.key.derived.origin.components_count);
        TEST_ASSERT_EQUAL(path_component_type_index, output.output.key.key.hdkey.key.derived.origin.components[0].type);
        TEST_ASSERT_TRUE(output.output.key.key.hdkey.key.derived.origin.components[0].component.index.is_hardened);
        TEST_ASSERT_EQUAL(48, output.output.key.key.hdkey.key.derived.origin.components[0].component.index.index);
        TEST_ASSERT_EQUAL(path_component_type_index, output.output.key.key.hdkey.key.derived.origin.components[1].type);
        TEST_ASSERT_TRUE(output.output.key.key.hdkey.key.derived.origin.components[1].component.index.is_hardened);
        TEST_ASSERT_EQUAL(0, output.output.key.key.hdkey.key.derived.origin.components[1].component.index.index);
        TEST_ASSERT_EQUAL(path_component_type_index, output.output.key.key.hdkey.key.derived.origin.components[2].type);
        TEST_ASSERT_TRUE(output.output.key.key.hdkey.key.derived.origin.components[2].component.index.is_hardened);
        TEST_ASSERT_EQUAL(0, output.output.key.key.hdkey.key.derived.origin.components[2].component.index.index);
        TEST_ASSERT_EQUAL(path_component_type_index, output.output.key.key.hdkey.key.derived.origin.components[3].type);
        TEST_ASSERT_TRUE(output.output.key.key.hdkey.key.derived.origin.components[3].component.index.is_hardened);
        TEST_ASSERT_EQUAL(2, output.output.key.key.hdkey.key.derived.origin.components[3].component.index.index);
        TEST_ASSERT_EQUAL(934670036, output.output.key.key.hdkey.key.derived.origin.source_fingerprint);
        TEST_ASSERT_FALSE(output.output.key.key.hdkey.key.derived.valid_children);
        TEST_ASSERT_EQUAL(1505139498, output.output.key.key.hdkey.key.derived.parent_fingerprint);
    }
}

int main() {
    UNITY_BEGIN();
    RUN_TEST(test_crypto_seed_parse);
    RUN_TEST(test_crypto_psbt_parse);
    RUN_TEST(test_crypto_eckey_parse);
    RUN_TEST(test_crypto_hdkey_parse_1);
    RUN_TEST(test_crypto_hdkey_parse_2);
    RUN_TEST(test_crypto_output_parse_1);
    RUN_TEST(test_crypto_output_parse_2);
    RUN_TEST(test_crypto_output_parse_3);
    RUN_TEST(test_crypto_output_parse_4);
    RUN_TEST(test_crypto_output_parse_5);
    RUN_TEST(test_crypto_account_parse);
    return UNITY_END();
}
