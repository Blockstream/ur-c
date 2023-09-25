
#include "unity_fixture.h"

TEST_GROUP_RUNNER(parser) {
    RUN_TEST_CASE(parser, crypto_seed_parse);
    RUN_TEST_CASE(parser, crypto_psbt_parse);
    RUN_TEST_CASE(parser, crypto_eckey_parse);
    RUN_TEST_CASE(parser, crypto_hdkey_parse_1);
    RUN_TEST_CASE(parser, crypto_hdkey_parse_2);
    RUN_TEST_CASE(parser, crypto_output_parse_1);
    RUN_TEST_CASE(parser, crypto_output_parse_2);
    RUN_TEST_CASE(parser, crypto_output_parse_3);
    RUN_TEST_CASE(parser, crypto_output_parse_4);
    RUN_TEST_CASE(parser, crypto_output_parse_5);
    RUN_TEST_CASE(parser, crypto_account_parse);
    RUN_TEST_CASE(parser, crypto_jadeaccount_parse);
    RUN_TEST_CASE(parser, jaderesponse_parse);
}

static void RunAllTests(void)
{
  RUN_TEST_GROUP(parser);
}

int main(int argc, const char * argv[])
{
  return UnityMain(argc, argv, RunAllTests);
}
