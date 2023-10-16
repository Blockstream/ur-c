
#include "cbor.h"

#include "urc/crypto_eckey.h"

#include "macros.h"
#include "utils.h"
#include "internals.h"


urc_error parse_eckey(size_t size, const uint8_t *buffer, crypto_eckey *out) {
    CborParser parser;
    CborValue iter;
    CborError err;
    err = cbor_parser_init(buffer, size, cbor_flags, &parser, &iter);
    if (err != CborNoError) {
        urc_error result = {.tag = urc_error_tag_cborinternalerror, .internal.cbor = err};
        return result;
    }
    return internal_parse_eckey(&iter, out);
}

urc_error internal_parse_eckey(CborValue *iter, crypto_eckey *out) {
    out->type = eckey_type_na;
    urc_error result = {.tag = urc_error_tag_noerror};

    CHECK_IS_TYPE(iter, map, result, exit);

    CborValue map_item;
    CborError err;
    err = cbor_value_enter_container(iter, &map_item);
    CHECK_CBOR_ERROR(err, result, exit);

    // curve field is optional,if present it must be 0 = secp256k1
    if (is_map_key(&map_item, 1)) {
        ADVANCE(&map_item, result, exit);
        int curve_type;
        CHECK_IS_TYPE(&map_item, integer, result, exit)
        err = cbor_value_get_int(&map_item, &curve_type);
        CHECK_CBOR_ERROR(err, result, exit);
        if (curve_type != 0) {
            result.tag = urc_error_tag_unhandledcase;
            goto exit;
        }
        ADVANCE(&map_item, result, exit);
    }

    // private field is optional, false by default
    bool is_private = false;
    if (is_map_key(&map_item, 2)) {
        ADVANCE(&map_item, result, exit);

        CHECK_IS_TYPE(&map_item, boolean, result, exit)
        err = cbor_value_get_boolean(&map_item, &is_private);
        CHECK_CBOR_ERROR(err, result, exit);

        ADVANCE(&map_item, result, exit);
    }

    result = check_map_key(&map_item, 3);
    if (result.tag != urc_error_tag_noerror) {
        goto exit;
    }
    ADVANCE(&map_item, result, exit);

    if (is_private) {
        result = copy_fixed_size_byte_string(&map_item, (uint8_t *)&out->key.prvate, CRYPTO_ECKEY_PRIVATE_SIZE);
        if (result.tag != urc_error_tag_noerror) {
            goto exit;
        }
        out->type = eckey_type_private;
        goto leave_and_exit;
    }
    CHECK_IS_TYPE(&map_item, byte_string, result, exit);
    size_t len;
    err = cbor_value_get_string_length(&map_item, &len);
    CHECK_CBOR_ERROR(err, result, exit);
    if (len == CRYPTO_ECKEY_PUBLIC_COMPRESSED_SIZE) {
        result = copy_fixed_size_byte_string(&map_item, (uint8_t *)&out->key.public_compressed, CRYPTO_ECKEY_PUBLIC_COMPRESSED_SIZE);
        if (result.tag != urc_error_tag_noerror) {
            goto exit;
        }
        out->type = eckey_type_public_compressed;
        goto leave_and_exit;
    }
    if (len == CRYPTO_ECKEY_PUBLIC_UNCOMPRESSED_SIZE) {
        result =
            copy_fixed_size_byte_string(&map_item, (uint8_t *)&out->key.public_uncompressed, CRYPTO_ECKEY_PUBLIC_UNCOMPRESSED_SIZE);
        if (result.tag != urc_error_tag_noerror) {
            goto exit;
        }
        out->type = eckey_type_public_uncompressed;
        goto leave_and_exit;
    }
    result.tag = urc_error_tag_unhandledcase;

leave_and_exit:
    ADVANCE(&map_item, result, exit);
    LEAVE_CONTAINER_SAFELY(iter, &map_item, result, exit);
exit:
    return result;
}
