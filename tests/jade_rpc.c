
#include "unity_fixture.h"

#include "urc/core.h"
#include "urc/jade_rpc.h"

#include "helpers.h"

#define BUFLEN 1000

TEST_GROUP(jade_rpc);
TEST_SETUP(jade_rpc) {}
TEST_TEAR_DOWN(jade_rpc) {}

TEST(jade_rpc, parse_jade_pin) {
    const char *hex =
        "a26269646671726175746866726573756c74a16c687474705f72657175657374a266706172616d73a46475726c7382782f68747470733a2f2f6a6164"
        "6570696e2e626c6f636b73747265616d2e636f6d2f73746172745f68616e647368616b657855687474703a2f2f6d727278747136746a70626e626d37"
        "7668356a74366d706a63746e3767677966793577656776626566663378376a727a6e7161776c6d69642e6f6e696f6e2f73746172745f68616e647368"
        "616b65666d6574686f6464504f535466616363657074646a736f6e646461746160686f6e2d7265706c796e68616e647368616b655f696e6974";
    uint8_t raw[BUFLEN];
    size_t len = h2b(hex, BUFLEN, (uint8_t *)&raw);
    TEST_ASSERT_GREATER_THAN_INT(0, len);

    char *out = NULL;
    int result = urc_jade_rpc_parse(raw, len, &out);
    TEST_ASSERT_EQUAL_INT(URC_OK, result);

    const char *expected =
        "{\"id\":\"qrauth\",\"result\":{\"http_request\":{\"params\":{\"urls\":[\"https://jadepin.blockstream.com/"
        "start_handshake\",\"http://mrrxtq6tjpbnbm7vh5jt6mpjctn7ggyfy5wegvbeff3x7jrznqawlmid.onion/"
        "start_handshake\"],\"method\":\"POST\",\"accept\":\"json\",\"data\":\"\"},\"on-reply\":\"handshake_init\"}}}";
    TEST_ASSERT_EQUAL_STRING(expected, out);
    urc_string_free(out);
}
