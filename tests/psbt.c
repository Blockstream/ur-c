
#include "unity_fixture.h"

#include "urc/crypto_psbt.h"
#include "urc/core.h"

#include "helpers.h"

#define BUFLEN 1024

TEST_GROUP(psbt);

TEST_SETUP(psbt) {}
TEST_TEAR_DOWN(psbt) {}

TEST(psbt, test_vector_1)
{
    const char *psbt_hex =
        "70736274ff01009a020000000258e87a21b56daf0c23be8e7070456c336f7cbaa5c8757924f545887bb2abdd750000000000ffffffff838d0427d0ec"
        "650a68aa46bb0b098aea4422c071b2ca78352a077959d07cea1d0100000000ffffffff0270aaf00800000000160014d85c2b71d0060b09c9886aeb81"
        "5e50991dda124d00e1f5050000000016001400aea9a2e5f0f876a588df5546e8742d1d87008f000000000000000000";
    const char *cbor_psbt_hex =
        "58a770736274ff01009a020000000258e87a21b56daf0c23be8e7070456c336f7cbaa5c8757924f545887bb2abdd750000000000ffffffff838d0427"
        "d0ec650a68aa46bb0b098aea4422c071b2ca78352a077959d07cea1d0100000000ffffffff0270aaf00800000000160014d85c2b71d0060b09c9886a"
        "eb815e50991dda124d00e1f5050000000016001400aea9a2e5f0f876a588df5546e8742d1d87008f000000000000000000";

    uint8_t raw_psbt[BUFLEN];
    size_t raw_len = h2b(psbt_hex, BUFLEN, (uint8_t *)&raw_psbt);
    TEST_ASSERT_GREATER_THAN_INT(0, raw_len);

    uint8_t raw_cbor_psbt[BUFLEN];
    size_t cbor_len = h2b(cbor_psbt_hex, BUFLEN, (uint8_t *)&raw_cbor_psbt);
    TEST_ASSERT_GREATER_THAN_INT(0, cbor_len);

    crypto_psbt psbt;
    psbt.psbt = raw_psbt;
    psbt.psbt_len = raw_len;
    uint8_t *buffer;
    size_t buffer_len;
    int result = urc_crypto_psbt_serialize(&psbt, &buffer, &buffer_len);
    TEST_ASSERT_EQUAL(URC_OK, result);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(raw_cbor_psbt, buffer, buffer_len);
    urc_free(buffer);

    result = urc_crypto_psbt_deserialize(raw_cbor_psbt, cbor_len, &psbt);
    TEST_ASSERT_EQUAL(URC_OK, result);
    TEST_ASSERT_EQUAL(raw_len, psbt.psbt_len);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(raw_psbt, psbt.psbt, raw_len);
}
