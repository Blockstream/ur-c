
#include "wally_core.h"

#include "urc/crypto_psbt.h"
#include "urc/error.h"

#include "macros.h"
#include "utils.h"

// max_len represents the maximum length of the psbt buffer
// if cbor byte string length is greater than max_len, return URC_EINVALIDARG
// max_len == 0 means no limit
int urc_crypto_psbt_deserialize_impl(CborValue *iter, crypto_psbt *out, size_t max_len);

int urc_crypto_psbt_deserialize(const uint8_t *cbor_buffer, size_t cbor_len, crypto_psbt *out)
{
    if (!cbor_buffer || !out) {
        return URC_EINVALIDARG;
    }

    CborParser parser;
    CborValue iter;
    CborError err;
    err = cbor_parser_init(cbor_buffer, cbor_len, cbor_flags, &parser, &iter);
    if (err != CborNoError) {
        return URC_ECBORINTERNALERROR;
    }
    return urc_crypto_psbt_deserialize_impl(&iter, out, cbor_len);
}

int urc_crypto_psbt_deserialize_impl(CborValue *iter, crypto_psbt *out, size_t max_len)
{
    out->psbt = NULL;
    out->psbt_len = 0;
    int result = URC_OK;

    CHECK_IS_TYPE(iter, byte_string, result, exit)
    size_t len;
    CborError err = cbor_value_get_string_length(iter, &len);
    CHECK_CBOR_ERROR(err, result, exit);
    if (len == 0 || (max_len && len > max_len)) {
        return URC_EINVALIDARG;
    }

    out->psbt = wally_malloc(len);
    if (!out->psbt) {
        return URC_ENOMEM;
    }

    result = copy_fixed_size_byte_string(iter, out->psbt, len);
    if (result != URC_OK) {
        goto free_and_exit;
    }
    out->psbt_len = len;

    ADVANCE(iter, result, free_and_exit);
    return URC_OK;

free_and_exit:
    urc_crypto_psbt_free(out);
exit:
    return result;
}

int urc_crypto_psbt_serialize_impl(const crypto_psbt *psbt, uint8_t *out, size_t *out_len)
{
    CborEncoder encoder;
    cbor_encoder_init(&encoder, out, *out_len, 0);
    CborError err = cbor_encode_byte_string(&encoder, psbt->psbt, psbt->psbt_len);
    if (err == CborErrorOutOfMemory) {
        return URC_EBUFFERTOOSMALL;
    }
    if (err != CborNoError) {
        return URC_ECBORINTERNALERROR;
    }
    *out_len = cbor_encoder_get_buffer_size(&encoder, out);
    return URC_OK;
}

int urc_crypto_psbt_serialize(const crypto_psbt *psbt, uint8_t **cbor_out, size_t *cbor_len)
{
    if (!psbt || !cbor_out) {
        return URC_EINVALIDARG;
    }
    *cbor_len = 0;
    *cbor_out = NULL;

    size_t buffer_len = psbt->psbt_len * 2 + 1;
    int result = URC_OK;
    *cbor_out = NULL;
    do {
        wally_free(*cbor_out);
        *cbor_out = wally_malloc(buffer_len);
        if (!*cbor_out) {
            return URC_ENOMEM;
        }
        *cbor_len = buffer_len;
        result = urc_crypto_psbt_serialize_impl(psbt, *cbor_out, cbor_len);
        buffer_len *= 2;
    } while (result == URC_EBUFFERTOOSMALL);
    if (result != URC_OK) {
        wally_free(*cbor_out);
        *cbor_out = NULL;
        *cbor_len = 0;
    }
    return result;
}

void urc_crypto_psbt_free(crypto_psbt *psbt)
{
    if (psbt) {
        wally_free(psbt->psbt);
        psbt->psbt = NULL;
        psbt->psbt_len = 0;
    }
}
