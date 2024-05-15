
#include "urc/crypto_psbt.h"
#include "urc/error.h"

#include "macros.h"
#include "utils.h"

int urc_crypto_psbt_deserialize_impl(CborValue *iter, crypto_psbt *out);

int urc_crypto_psbt_deserialize(const uint8_t *buffer, size_t len, crypto_psbt *out)
{
    CborParser parser;
    CborValue iter;
    CborError err;
    err = cbor_parser_init(buffer, len, cbor_flags, &parser, &iter);
    if (err != CborNoError) {
        return URC_ECBORINTERNALERROR;
    }
    return urc_crypto_psbt_deserialize_impl(&iter, out);
}

int urc_crypto_psbt_deserialize_impl(CborValue *iter, crypto_psbt *out)
{
    out->psbt_len = 0;
    int result = URC_OK;

    CHECK_IS_TYPE(iter, byte_string, result, exit)
    size_t len;
    CborError err = cbor_value_get_string_length(iter, &len);
    CHECK_CBOR_ERROR(err, result, exit);

    if (out->buffer_size < len) {
        return URC_EBUFFERTOOSMALL;
    }

    len = out->buffer_size;
    err = cbor_value_copy_byte_string(iter, out->buffer, &len, NULL);
    CHECK_CBOR_ERROR(err, result, exit);

    out->psbt_len = len;

    ADVANCE(iter, result, exit);

exit:
    return result;
}
