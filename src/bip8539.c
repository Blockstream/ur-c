
#include "urc/crypto_eckey.h"
#include "urc/error.h"
#include "urc/jade_bip8539.h"

#include "macros.h"
#include "utils.h"

static int jade_bip8539_request_format_impl(CborEncoder *encoder, const jade_bip8539_request *request) {
    CborError err;
    CborEncoder map;
    err = cbor_encoder_create_map(encoder, &map, 3);
    if (err == CborNoError)
        err = cbor_encode_text_stringz(&map, "num_words");
    if (err == CborNoError)
        err = cbor_encode_uint(&map, request->num_words);
    if (err == CborNoError)
        err = cbor_encode_text_stringz(&map, "index");
    if (err == CborNoError)
        err = cbor_encode_uint(&map, request->index);
    if (err == CborNoError)
        err = cbor_encode_text_stringz(&map, "pubkey");
    if (err == CborNoError)
        err = cbor_encode_byte_string(&map, request->pubkey, CRYPTO_ECKEY_PUBLIC_COMPRESSED_SIZE);
    if (err == CborNoError)
        err = cbor_encoder_close_container(encoder, &map);

    if (err == CborErrorOutOfMemory)
        return URC_EBUFFERTOOSMALL;
    if (err != CborNoError)
        return URC_ECBORINTERNALERROR;

    return URC_OK;
}

static int jade_bip8539_response_parse_impl(CborValue *iter, jade_bip8539_response *out, uint8_t *buffer, size_t len) {
    out->encrypted_len = 0;
    int result = URC_OK;

    CHECK_IS_TYPE(iter, map, result, exit)

    CborValue element;
    CborError err = cbor_value_map_find_value(iter, "pubkey", &element);
    CHECK_CBOR_ERROR(err, result, exit);

    if (element.type == CborInvalidType) {
        result = URC_EUNKNOWNFORMAT;
        goto exit;
    }
    CHECK_IS_TYPE(&element, byte_string, result, exit);
    result = copy_fixed_size_byte_string(&element, (uint8_t *)&out->pubkey, CRYPTO_ECKEY_PUBLIC_COMPRESSED_SIZE);
    if (result != URC_OK) {
        goto exit;
    }

    err = cbor_value_map_find_value(iter, "encrypted", &element);
    CHECK_CBOR_ERROR(err, result, exit);

    CHECK_IS_TYPE(&element, byte_string, result, exit);
    err = cbor_value_copy_byte_string(&element, buffer, &len, NULL);
    CHECK_CBOR_ERROR(err, result, exit);

    out->encrypted_len = len;
    out->encripted_data = buffer;
exit:
    return result;
}

int urc_jade_bip8539_request_format(const jade_bip8539_request *request, uint8_t *out, size_t *len) {
    CborEncoder encoder;
    cbor_encoder_init(&encoder, out, *len, 0);

    int result = jade_bip8539_request_format_impl(&encoder, request);
    if (result == URC_OK) {
        *len = cbor_encoder_get_buffer_size(&encoder, out);
    } else {
        *len = 0;
    }
    return result;
}

int urc_jade_bip8539_response_parse(const uint8_t *cbor, size_t cbor_len, jade_bip8539_response *response, uint8_t *buffer,
                                    size_t buffer_len) {
    CborParser parser;
    CborValue iter;
    CborError err;
    err = cbor_parser_init(cbor, cbor_len, cbor_flags, &parser, &iter);
    if (err != CborNoError) {
        return URC_ECBORINTERNALERROR;
    }
    return jade_bip8539_response_parse_impl(&iter, response, buffer, buffer_len);
}
