
#include "urc/jade_bip8539.h"

#include "macros.h"
#include "utils.h"
#include <cbor.h>

urc_error internal_format_jaderequest(CborEncoder *encoder, const jade_request *request);

urc_error format_jaderequest(const jade_request *request, size_t size, uint8_t *out) {
    CborEncoder encoder;
    cbor_encoder_init(&encoder, out, size, 0);

    return internal_format_jaderequest(&encoder, request);
}

urc_error internal_format_jaderequest(CborEncoder *encoder, const jade_request *request) {
    urc_error result = {.tag = urc_error_tag_noerror};

    CborEncoder map;
    CborError err = cbor_encoder_create_map(encoder, &map, 3);
    CHECK_CBOR_ERROR(err, result, exit);
    {
        err = cbor_encode_text_stringz(&map, "num_words");
        CHECK_CBOR_ERROR(err, result, exit);
        err = cbor_encode_uint(&map, request->words);
        CHECK_CBOR_ERROR(err, result, exit);
    }
    {
        err = cbor_encode_text_stringz(&map, "index");
        CHECK_CBOR_ERROR(err, result, exit);
        err = cbor_encode_uint(&map, request->index);
        CHECK_CBOR_ERROR(err, result, exit);
    }
    {
        err = cbor_encode_text_stringz(&map, "pubkey");
        CHECK_CBOR_ERROR(err, result, exit);
        err = cbor_encode_byte_string(&map, request->pubkey, CRYPTO_ECKEY_PUBLIC_COMPRESSED_SIZE);
        CHECK_CBOR_ERROR(err, result, exit);
    }
    err = cbor_encoder_close_container(encoder, &map);
    CHECK_CBOR_ERROR(err, result, exit);

exit:
    return result;
}

urc_error internal_parse_jaderesponse(CborValue *iter, jade_response *out);

urc_error parse_jaderesponse(size_t size, const uint8_t *buffer, jade_response *out) {
    CborParser parser;
    CborValue iter;
    CborError err;
    err = cbor_parser_init(buffer, size, cbor_flags, &parser, &iter);
    if (err != CborNoError) {
        urc_error result = {.tag = urc_error_tag_cborinternalerror, .internal.cbor = err};
        return result;
    }
    return internal_parse_jaderesponse(&iter, out);
}

urc_error internal_parse_jaderesponse(CborValue *iter, jade_response *out) {
    out->encrypted_len = 0;
    urc_error result = {.tag = urc_error_tag_noerror};

    CHECK_IS_TYPE(iter, map, result, exit)

    {
        CborValue element;
        CborError err = cbor_value_map_find_value(iter, "pubkey", &element);
        CHECK_CBOR_ERROR(err, result, exit);

        if (element.type == CborInvalidType) {
            result.tag = urc_error_tag_unknownformat;
            goto exit;
        }
        CHECK_IS_TYPE(&element, byte_string, result, exit);
        result = copy_fixed_size_byte_string(&element, CRYPTO_ECKEY_PUBLIC_COMPRESSED_SIZE, (uint8_t *)&out->pubkey);
        if (result.tag != urc_error_tag_noerror) {
            goto exit;
        }
    }
    {
        CborValue element;
        CborError err = cbor_value_map_find_value(iter, "encrypted", &element);
        CHECK_CBOR_ERROR(err, result, exit);

        if (element.type == CborInvalidType) {
            result.tag = urc_error_tag_unknownformat;
            goto exit;
        }
        CHECK_IS_TYPE(&element, byte_string, result, exit);
        out->encrypted_len = out->buffer_size;
        err = cbor_value_copy_byte_string(&element, out->buffer, &out->encrypted_len, NULL);
        CHECK_CBOR_ERROR(err, result, exit);
    }

exit:
    return result;
}
