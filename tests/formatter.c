
#include "unity.h"
#include "unity_fixture.h"

#include "urc/jade_bip8539.h"
#include "urc/urc.h"

#include "helpers.h"
#include <cbor.h>

#define BUFLEN 1000
#define SMALLBUFLEN 20

TEST_GROUP(formatter);

TEST_SETUP(formatter) {}
TEST_TEAR_DOWN(formatter) {}

TEST(formatter, jaderequest_format) {
    jade_bip8539_request request;
    request.num_words = 24;
    request.index = 1024;
    const char *pubkey = "037aa2120135ae201c0586ad9f450ad3f4641ddabcd9bd3e692944d9d8fd8ed8d2";
    size_t len = h2b(pubkey, CRYPTO_ECKEY_PUBLIC_COMPRESSED_SIZE, (uint8_t *)&request.pubkey);
    TEST_ASSERT_EQUAL(CRYPTO_ECKEY_PUBLIC_COMPRESSED_SIZE, len);

    uint8_t buffer[BUFLEN];
    int err = urc_jade_bip8539_request_format(&request, buffer, BUFLEN);
    TEST_ASSERT_EQUAL(URC_OK, err);
    const char *expected = "a3696e756d5f776f726473181865696e646578190400667075626b65795821037aa2120135ae201c0586ad9f450ad3f4641dd"
                           "abcd9bd3e692944d9d8fd8ed8d2";

    uint8_t bufferexpected[BUFLEN];
    len = h2b(expected, strlen(expected), bufferexpected);
    TEST_ASSERT_GREATER_THAN(0, len);

    TEST_ASSERT_EQUAL_UINT8_ARRAY(bufferexpected, buffer, len);
}

TEST(formatter, jaderequest_format_smallbuffer) {
    jade_bip8539_request request;
    request.num_words = 24;
    request.index = 1024;
    const char *pubkey = "037aa2120135ae201c0586ad9f450ad3f4641ddabcd9bd3e692944d9d8fd8ed8d2";
    size_t len = h2b(pubkey, CRYPTO_ECKEY_PUBLIC_COMPRESSED_SIZE, (uint8_t *)&request.pubkey);
    TEST_ASSERT_EQUAL(CRYPTO_ECKEY_PUBLIC_COMPRESSED_SIZE, len);

    uint8_t buffer[SMALLBUFLEN];
    int err = urc_jade_bip8539_request_format(&request, buffer, SMALLBUFLEN);
    TEST_ASSERT_EQUAL(URC_EBUFFERTOOSMALL, err);
}
