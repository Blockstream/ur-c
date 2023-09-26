
#include "unity.h"
#include "unity_fixture.h"

#include "urc/jade_bip8539.h"
#include "urc/urc.h"

#include "helpers.h"
#include <cbor.h>

#define BUFSIZE 1000
#define SMALLBUFSIZE 20

TEST_GROUP(formatter);

TEST_SETUP(formatter) {}
TEST_TEAR_DOWN(formatter) {}

TEST(formatter, jaderequest_format) {
    jade_request request;
    request.words = 24;
    request.index = 1024;
    const char *pubkey = "037aa2120135ae201c0586ad9f450ad3f4641ddabcd9bd3e692944d9d8fd8ed8d2";
    size_t size = h2b(pubkey, CRYPTO_ECKEY_PUBLIC_COMPRESSED_SIZE, (uint8_t *)&request.pubkey);
    TEST_ASSERT_EQUAL(CRYPTO_ECKEY_PUBLIC_COMPRESSED_SIZE, size);

#ifdef WALLYFIED
    uint8_t *buffer;
    size_t outsize;
    urc_error err = format_jaderequest(&request, &outsize, &buffer);
#else
    uint8_t buffer[BUFSIZE];
    urc_error err = format_jaderequest(&request, BUFSIZE, buffer);
#endif
    TEST_ASSERT_EQUAL(urc_error_tag_noerror, err.tag);
    const char *expected = "a3696e756d5f776f726473181865696e646578190400667075626b65795821037aa2120135ae201c0586ad9f450ad3f4641dd"
                           "abcd9bd3e692944d9d8fd8ed8d2";

    uint8_t bufferexpected[BUFSIZE];
    size = h2b(expected, strlen(expected), bufferexpected);
    TEST_ASSERT_GREATER_THAN(0, size);

    TEST_ASSERT_EQUAL_UINT8_ARRAY(bufferexpected, buffer, size);
}

TEST(formatter, jaderequest_format_smallbuffer) {
    jade_request request;
    request.words = 24;
    request.index = 1024;
    const char *pubkey = "037aa2120135ae201c0586ad9f450ad3f4641ddabcd9bd3e692944d9d8fd8ed8d2";
    size_t size = h2b(pubkey, CRYPTO_ECKEY_PUBLIC_COMPRESSED_SIZE, (uint8_t *)&request.pubkey);
    TEST_ASSERT_EQUAL(CRYPTO_ECKEY_PUBLIC_COMPRESSED_SIZE, size);

#ifdef WALLYFIED
    uint8_t *out;
    size_t outsize;
    urc_error err = format_jaderequest(&request, &outsize, &out);
    TEST_ASSERT_EQUAL(urc_error_tag_noerror, err.tag);
#else
    uint8_t buffer[SMALLBUFSIZE];
    urc_error err = format_jaderequest(&request, SMALLBUFSIZE, buffer);
    TEST_ASSERT_EQUAL(urc_error_tag_cborinternalerror, err.tag);
    TEST_ASSERT_EQUAL(CborErrorOutOfMemory, err.internal.cbor);
#endif
}
