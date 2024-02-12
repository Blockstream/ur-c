
#include "unity_fixture.h"

#include "urc/core.h"
#include "urc/jade_rpc.h"

#include "helpers.h"

#define BUFLEN 1000

TEST_GROUP(jade_rpc);
TEST_SETUP(jade_rpc) {}
TEST_TEAR_DOWN(jade_rpc) {}

TEST(jade_rpc, parse_jade_pin_1)
{
    const char *hex =
        "a26269646671726175746866726573756c74a16c687474705f72657175657374a266706172616d73a46475726c7382782f68747470733a2f2f6a6164"
        "6570696e2e626c6f636b73747265616d2e636f6d2f73746172745f68616e647368616b657855687474703a2f2f6d727278747136746a70626e626d37"
        "7668356a74366d706a63746e3767677966793577656776626566663378376a727a6e7161776c6d69642e6f6e696f6e2f73746172745f68616e647368"
        "616b65666d6574686f6464504f535466616363657074646a736f6e646461746160686f6e2d7265706c796e68616e647368616b655f696e6974";
    uint8_t raw[BUFLEN];
    size_t len = h2b(hex, BUFLEN, (uint8_t *)&raw);
    TEST_ASSERT_GREATER_THAN_INT(0, len);

    char *out = NULL;
    int result = urc_jade_rpc_deserialize(raw, len, &out);
    TEST_ASSERT_EQUAL_INT(URC_OK, result);

    const char *expected =
        "{\"id\":\"qrauth\",\"result\":{\"http_request\":{\"params\":{\"urls\":[\"https://jadepin.blockstream.com/"
        "start_handshake\",\"http://mrrxtq6tjpbnbm7vh5jt6mpjctn7ggyfy5wegvbeff3x7jrznqawlmid.onion/"
        "start_handshake\"],\"method\":\"POST\",\"accept\":\"json\",\"data\":\"\"},\"on-reply\":\"handshake_init\"}}}";
    TEST_ASSERT_EQUAL_STRING(expected, out);
    urc_string_free(out);
}

TEST(jade_rpc, parse_jade_pin_2)
{
    const char *hex =
        "a26269646671726175746866726573756c74a16c687474705f72657175657374a266706172616d73a46475726c7382782f68747470733a2f2f6a6164"
        "6570696e2d73746167696e672e626c6f636b73747265616d2e636f6d2f6765745f70696e60666d6574686f6464504f535466616363657074646a736f"
        "6e6464617461a16464617461790108412b324e446e4f63412b53454c58793675374267354d6b3931506c70666136714279354d715376794a4f717659"
        "774141414365716c5273626c4431756d4f74337856706c494b5673583932323464555a2b6348514662416836662f7673756c6b7572326451782b4e34"
        "795437566c6e4a6e55692b384569316c68715333704463674562622b726e5a6432744262695648554f41414d4d68687a44394b3361514e396332494e"
        "72367546585846386733615731527478462f367878336b4453693137644d48425a76764a746151776576437a7a64514c564a2b506853393367514e6e"
        "66774c7966714649726b646851555368716a6242566151776a4b2f6547466f676f366e4e63733d686f6e2d7265706c796370696e";
    uint8_t raw[BUFLEN];
    size_t len = h2b(hex, BUFLEN, (uint8_t *)&raw);
    TEST_ASSERT_GREATER_THAN_INT(0, len);

    char *out = NULL;
    int result = urc_jade_rpc_deserialize(raw, len, &out);
    TEST_ASSERT_EQUAL_INT(URC_OK, result);

    const char *expected =
        "{\"id\":\"qrauth\",\"result\":{\"http_request\":{\"params\":{\"urls\":[\"https://jadepin-staging.blockstream.com/"
        "get_pin\",\"\"],\"method\":\"POST\",\"accept\":\"json\",\"data\":{\"data\":\"A+2NDnOcA+"
        "SELXy6u7Bg5Mk91Plpfa6qBy5MqSvyJOqvYwAAACeqlRsblD1umOt3xVplIKVsX9224dUZ+cHQFbAh6f/"
        "vsulkur2dQx+N4yT7VlnJnUi+8Ei1lhqS3pDcgEbb+rnZd2tBbiVHUOAAMMhhzD9K3aQN9c2INr6uFXXF8g3aW1RtxF/"
        "6xx3kDSi17dMHBZvvJtaQwevCzzdQLVJ+PhS93gQNnfwLyfqFIrkdhQUShqjbBVaQwjK/eGFogo6nNcs=\"}},\"on-reply\":\"pin\"}}}";
    TEST_ASSERT_EQUAL_STRING(expected, out);
    urc_string_free(out);
}

TEST(jade_rpc, parse_jade_pin_3)
{
    const char *hex =
        "a36269646130666d6574686f646370696e66706172616d73a164646174617880377948355850466434675050425472596d5a75756659513961436770"
        "716355656c432b796437495845354d456239695171616b78744e7a7a6265382f51385669566f4e657053714c3355494565416a655734483052334d70"
        "32594d4c416b3942664b3961326a64495a4f2f774b464f3576704d6b464949724552452f5751382b";
    uint8_t raw[BUFLEN];
    size_t len = h2b(hex, BUFLEN, (uint8_t *)&raw);
    TEST_ASSERT_GREATER_THAN_INT(0, len);

    char *out = NULL;
    int result = urc_jade_rpc_deserialize(raw, len, &out);
    TEST_ASSERT_EQUAL_INT(URC_OK, result);

    const char *expected = "{\"id\":\"0\",\"method\":\"pin\",\"params\":{\"data\":\"7yH5XPFd4gPPBTrYmZuufYQ9aCgpqcUelC+"
                           "yd7IXE5MEb9iQqakxtNzzbe8/Q8ViVoNepSqL3UIEeAjeW4H0R3Mp2YMLAk9BfK9a2jdIZO/wKFO5vpMkFIIrERE/WQ8+\"}}";
    TEST_ASSERT_EQUAL_STRING(expected, out);
    urc_string_free(out);
}
