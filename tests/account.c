
#include <string.h>

#include "unity.h"
#include "unity_fixture.h"

#include "urc/core.h"
#include "urc/crypto_account.h"

#include "helpers.h"
#include "urc/error.h"

#define BUFLEN 1024

TEST_GROUP(account);

TEST_SETUP(account) {}
TEST_TEAR_DOWN(account) {}

TEST(account, test_vector_1)
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

    const size_t expected_desc_size = 6;
    const char *expected_desc[] = {
        "pkh([37b5eed4/44'/0'/"
        "0']xpub6CnQkivUEH9bSbWVWfDLCtigKKgnSWGaVSRyCbN2QNBJzuvHT1vUQpgSpY1NiVvoeNEuVwk748Cn9G3NtbQB1aGGsEL7aYEnjVWgjj9tefu)",
        "sh(wpkh([37b5eed4/49'/0'/"
        "0']xpub6CtR1iF4dZPkEyXDwVf3HE74tSwXNMcHtBzX4gwz2UnPhJ54Jz5unHx2syYCCDkvVUmsmoYTmcaHXe1wJppvct4GMMaN5XAbRk7yGScRSte)"
        ")",
        "wpkh([37b5eed4/84'/0'/"
        "0']xpub6BkU445MSEBXbPjD3g2c2ch6mn8yy1SXXQUM7EwjgYiq6Wt1NDwDZ45npqWcV8uQC5oi2gHuVukoCoZZyT4HKq8EpotPMqGqxdZRuapCQ23)",
        "sh(cosigner([37b5eed4/"
        "45']xpub68JFLJTH96GUqC6SoVw5c2qyLSt776PGu5xde8ddVACuPYyarvSL827TbZGavuNbKQ8DG3VP9fCXPhQRBgPrS4MPG3zaZgwAGuPHYvVuY9X))",
        "sh(wsh(cosigner([37b5eed4/48'/0'/0'/"
        "1']xpub6EC9f7mLFJQoPaqDJ72Zbv67JWzmpXvCYQSecER9GzkYy5eWLsVLbHnxoAZ8NnnsrjhMLduJo9dG6fNQkmMFL3Qedj2kf5bEy5tptHPApNf)))",
        "wsh(cosigner([37b5eed4/48'/0'/0'/"
        "2']xpub6EC9f7mLFJQoRQ6qiTvWQeeYsgtki6fBzSUgWgUtAujEMtAfJSAn3AVS4KrLHRV2hNX77YwNkg4azUzuSwhNGtcq4r2J8bLGMDkrQYHvoed))"};
    const uint32_t expected_fpr = 934670036;

    uint8_t raw[BUFLEN];
    size_t len = h2b(hex, BUFLEN, (uint8_t *)(&raw));
    TEST_ASSERT_GREATER_THAN_INT(0, len);

    crypto_account account;
    int err = urc_crypto_account_deserialize(raw, len, &account);
    TEST_ASSERT_EQUAL(URC_ETAPROOTNOTSUPPORTED, err);

    TEST_ASSERT_EQUAL(expected_fpr, account.master_fingerprint);
    TEST_ASSERT_EQUAL(expected_desc_size, account.descriptors_count);

    char **descs;
    err = urc_crypto_account_format(&account, urc_crypto_output_format_mode_default, &descs);
    TEST_ASSERT_EQUAL(URC_OK, err);
    TEST_ASSERT_EQUAL_STRING_ARRAY(expected_desc, descs, expected_desc_size);
    TEST_ASSERT_NULL(descs[expected_desc_size]);

    urc_string_array_free(descs);
}

TEST(account, jade)
{
    const char *hex =
        "a2011ab6215d6b0281d90194d9012fa4035821025d6aca89f721020f672d1653f87d171c1ad4103a24e8eaa3a07c596bc6652f7a045820e6b977baf5"
        "cd1a24eedb65292c78b4680f658ab11aeff1671d5246f71636860b06d90130a301861854f500f500f5021ab6215d6b0303081a97538da9";

    const size_t expected_desc_size = 1;
    const char *expected_desc[] = {
        "wpkh([b6215d6b/84'/0'/"
        "0']xpub6CmHFAns2t9zT1HUC5YFEjzcNiwUdQEiez6o2NvVSRvrk5nC3s8mwW57GvPNCEJ2tQTpVa21Gyu4GJgUPfT3NgahVcsTiNCQnMXXTkpq5Ld/0/"
        "*)"};
    const uint32_t expected_fpr = 3055639915;

    uint8_t raw[BUFLEN];
    size_t len = h2b(hex, BUFLEN, (uint8_t *)(&raw));
    TEST_ASSERT_GREATER_THAN_INT(0, len);

    crypto_account account;
    int err = urc_jade_account_deserialize(raw, len, &account);
    TEST_ASSERT_EQUAL(URC_OK, err);

    TEST_ASSERT_EQUAL(expected_fpr, account.master_fingerprint);
    TEST_ASSERT_EQUAL(expected_desc_size, account.descriptors_count);

    char **descs;
    err = urc_crypto_account_format(&account, urc_crypto_output_format_mode_BIP44_compatible, &descs);
    TEST_ASSERT_NULL(descs[expected_desc_size]);
    TEST_ASSERT_EQUAL_STRING_ARRAY(expected_desc, descs, expected_desc_size);

    urc_string_array_free(descs);
}
