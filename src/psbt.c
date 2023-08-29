
#include "urc/crypto_psbt.h"

#include "macros.h"
#include "utils.h"

urc_error internal_parse_psbt(CborValue *iter, crypto_psbt *out);

urc_error parse_psbt(size_t size, const uint8_t *buffer, crypto_psbt *out) {
    CborParser parser;
    CborValue iter;
    CborError err;
    err = cbor_parser_init(buffer, size, cbor_flags, &parser, &iter);
    if (err != CborNoError) {
        urc_error result = {.tag = urc_error_tag_cborinternalerror, .internal.cbor = err};
        return result;
    }
    return internal_parse_psbt(&iter, out);
}

urc_error internal_parse_psbt(CborValue *iter, crypto_psbt *out) {
    out->psbt_len = 0;
    urc_error result = {.tag = urc_error_tag_noerror};

    CHECK_IS_TYPE(iter, byte_string, result, exit)
    size_t len;
    CborError err = cbor_value_get_string_length(iter, &len);
    CHECK_CBOR_ERROR(err, result, exit);

    if (out->buffer_size < len) {
        result.tag = urc_error_tag_wrongstringlength;
        return result;
    }

    len = out->buffer_size;
    err = cbor_value_copy_byte_string(iter, out->buffer, &len, NULL);
    CHECK_CBOR_ERROR(err, result, exit);

    out->psbt_len = len;

    ADVANCE(iter, result, exit);

exit:
    return result;
}
