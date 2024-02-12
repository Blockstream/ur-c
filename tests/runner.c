
#include "unity_fixture.h"

TEST_GROUP_RUNNER(parser) {
    RUN_TEST_CASE(parser, crypto_seed_deserialize);
    RUN_TEST_CASE(parser, crypto_psbt_deserialize);
    RUN_TEST_CASE(parser, crypto_eckey_deserialize);
    RUN_TEST_CASE(parser, crypto_hdkey_deserialize_1);
    RUN_TEST_CASE(parser, crypto_hdkey_deserialize_2);
    RUN_TEST_CASE(parser, crypto_output_deserialize_1);
    RUN_TEST_CASE(parser, crypto_output_deserialize_2);
    RUN_TEST_CASE(parser, crypto_output_deserialize_3);
    RUN_TEST_CASE(parser, crypto_output_deserialize_4);
    RUN_TEST_CASE(parser, crypto_output_deserialize_5);
    RUN_TEST_CASE(parser, crypto_account_deserialize);
    RUN_TEST_CASE(parser, crypto_jadeaccount_deserialize);
    RUN_TEST_CASE(parser, jaderesponse_deserialize);
}

TEST_GROUP_RUNNER(formatter) {
    RUN_TEST_CASE(formatter, jaderequest_format);
}

TEST_GROUP_RUNNER(jade_rpc) {
    RUN_TEST_CASE(jade_rpc, parse_jade_pin_1);
    RUN_TEST_CASE(jade_rpc, parse_jade_pin_2);
    RUN_TEST_CASE(jade_rpc, parse_jade_pin_3);
}

static void RunAllTests(void) {
    RUN_TEST_GROUP(parser);
    RUN_TEST_GROUP(formatter);
    RUN_TEST_GROUP(jade_rpc);
}

int main(int argc, const char *argv[]) { return UnityMain(argc, argv, RunAllTests); }
