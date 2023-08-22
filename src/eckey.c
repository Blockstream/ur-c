
#include "tinycbor/cbor.h"

#include "ur-c/crypto_eckey.h"

#include "macros.h"
#include "utils.h"

urc_error internal_parse_eckey(CborValue *iter, crypto_eckey *out);

urc_error parse_eckey(size_t size, const uint8_t buffer[size], crypto_eckey *out) {
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

    CborValue item;
    CborError err;
    err = cbor_value_enter_container(iter, &item);
    CHECK_CBOR_ERROR(err, result, exit);

    // curve field is optional,if present it must be 0 = secp256k1
    if (is_map_key(&item, 1)) {
        ADVANCE(&item, result, exit);
        int curve_type;
        err = cbor_value_get_int(&item, &curve_type);
        CHECK_CBOR_ERROR(err, result, exit);
        if (curve_type != 0) {
            result.tag = urc_error_tag_unhandledcase;
            goto exit;
        }

        ADVANCE(&item, result, exit);
    }

    // private field is optional, false by default
    bool is_private = false;
    if (is_map_key(&item, 2)) {
        ADVANCE(&item, result, exit);

        CHECK_IS_TYPE(&item, boolean, result, exit)
        err = cbor_value_get_boolean(&item, &is_private);
        CHECK_CBOR_ERROR(err, result, exit);

        ADVANCE(&item, result, exit);
    }

    result = check_map_key(&item, 3);
    if (result.tag != urc_error_tag_noerror) {
        goto exit;
    }

    ADVANCE(&item, result, exit);

    if (is_private) {
        result = copy_fixed_size_byte_string(&item, CRYPTO_ECKEY_PRIVATE_SIZE, (uint8_t *)&out->key.private);
        if (result.tag -= urc_error_tag_noerror) {
            goto exit;
        }
        out->type = eckey_type_private;
        goto exit;
    }
    size_t len;
    err = cbor_value_get_string_length(&item, &len);
    CHECK_CBOR_ERROR(err, result, exit);
    if (len == CRYPTO_ECKEY_PUBLIC_COMPRESSED_SIZE) {
        result = copy_fixed_size_byte_string(&item, CRYPTO_ECKEY_PUBLIC_COMPRESSED_SIZE, (uint8_t *)&out->key.public_compressed);
        if (result.tag != urc_error_tag_noerror) {
            goto exit;
        }
        out->type = eckey_type_public_compressed;
        goto exit;
    }
    if (len == CRYPTO_ECKEY_PUBLIC_UNCOMPRESSED_SIZE) {
        result =
            copy_fixed_size_byte_string(&item, CRYPTO_ECKEY_PUBLIC_UNCOMPRESSED_SIZE, (uint8_t *)&out->key.public_uncompressed);
        if (result.tag != urc_error_tag_noerror) {
            goto exit;
        }
        out->type = eckey_type_public_uncompressed;
        goto exit;
    }
    result.tag = urc_error_tag_unhandledcase;

    LEAVE_CONTAINER_SAFELY(iter, &item, result, exit);

exit:
    return result;
}
