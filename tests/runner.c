
#include "unity_fixture.h"

TEST_GROUP_RUNNER(parser) {
    RUN_TEST_CASE(parser, crypto_seed_deserialize);
}

TEST_GROUP_RUNNER(formatter) {
    RUN_TEST_CASE(formatter, jaderequest_format);
}

TEST_GROUP_RUNNER(jade_rpc) {
    RUN_TEST_CASE(jade_rpc, parse_jade_pin_1);
    RUN_TEST_CASE(jade_rpc, parse_jade_pin_2);
    RUN_TEST_CASE(jade_rpc, parse_jade_pin_3);
}

TEST_GROUP_RUNNER(psbt) {
    RUN_TEST_CASE(psbt, test_vector_1);
}

TEST_GROUP_RUNNER(eckey) {
    RUN_TEST_CASE(eckey, test_vector_1);
    RUN_TEST_CASE(eckey, test_vector_2);
}

TEST_GROUP_RUNNER(hdkey) {
    RUN_TEST_CASE(hdkey, test_vector_1);
    RUN_TEST_CASE(hdkey, test_vector_2);
}

TEST_GROUP_RUNNER(output) {
    RUN_TEST_CASE(output, test_vector_1);
    RUN_TEST_CASE(output, test_vector_2);
    RUN_TEST_CASE(output, test_vector_4);
}

TEST_GROUP_RUNNER(account) {
    RUN_TEST_CASE(account, test_vector_1);
    RUN_TEST_CASE(account, jadetest);
    RUN_TEST_CASE(account, jade);
}

static void RunAllTests(void) {
    RUN_TEST_GROUP(parser);
    RUN_TEST_GROUP(formatter);
    RUN_TEST_GROUP(jade_rpc);
    RUN_TEST_GROUP(psbt);
    RUN_TEST_GROUP(eckey);
    RUN_TEST_GROUP(hdkey);
    RUN_TEST_GROUP(output);
    RUN_TEST_GROUP(account);
}

int main(int argc, const char *argv[]) { return UnityMain(argc, argv, RunAllTests); }
