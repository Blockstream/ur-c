
#include "urc/crypto_eckey.h"
#include "urc/error.h"

#include "internals.h"
#include "macros.h"
#include "utils.h"
#include <wally_core.h>

int urc_crypto_eckey_deserialize(const uint8_t *buffer, size_t len, crypto_eckey *out)
{
    CborParser parser;
    CborValue iter;
    CborError err;
    err = cbor_parser_init(buffer, len, cbor_flags, &parser, &iter);
    if (err != CborNoError) {
        return URC_ECBORINTERNALERROR;
    }
    return urc_crypto_eckey_deserialize_impl(&iter, out);
}

int urc_crypto_eckey_deserialize_impl(CborValue *iter, crypto_eckey *out)
{
    out->type = eckey_type_na;
    int result = URC_OK;

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
            result = URC_EUNHANDLEDCASE;
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
    if (result != URC_OK) {
        goto exit;
    }
    ADVANCE(&map_item, result, exit);

    if (is_private) {
        result = copy_fixed_size_byte_string(&map_item, (uint8_t *)&out->key.prvate, CRYPTO_ECKEY_PRIVATE_SIZE);
        if (result != URC_OK) {
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
        result =
            copy_fixed_size_byte_string(&map_item, (uint8_t *)&out->key.public_compressed, CRYPTO_ECKEY_PUBLIC_COMPRESSED_SIZE);
        if (result != URC_OK) {
            goto exit;
        }
        out->type = eckey_type_public_compressed;
        goto leave_and_exit;
    }
    if (len == CRYPTO_ECKEY_PUBLIC_UNCOMPRESSED_SIZE) {
        result = copy_fixed_size_byte_string(&map_item, (uint8_t *)&out->key.public_uncompressed,
                                             CRYPTO_ECKEY_PUBLIC_UNCOMPRESSED_SIZE);
        if (result != URC_OK) {
            goto exit;
        }
        out->type = eckey_type_public_uncompressed;
        goto leave_and_exit;
    }
    result = URC_EUNHANDLEDCASE;

leave_and_exit:
    ADVANCE(&map_item, result, exit);
    LEAVE_CONTAINER_SAFELY(iter, &map_item, result, exit);
exit:
    return result;
}

int urc_crypto_eckey_format(const crypto_eckey *eckey, char **out)
{
    if (!eckey || !out) {
        return URC_EINVALIDARG;
    }

    *out = NULL;
    int wallyerr = WALLY_OK;
    switch (eckey->type) {
    case eckey_type_private:
         wallyerr = wally_hex_from_bytes(eckey->key.prvate, CRYPTO_ECKEY_PRIVATE_SIZE, out);
        break;
    case eckey_type_public_compressed:
        wallyerr = wally_hex_from_bytes(eckey->key.public_compressed, CRYPTO_ECKEY_PUBLIC_COMPRESSED_SIZE, out);
        break;
    case eckey_type_public_uncompressed:
        wallyerr = wally_hex_from_bytes(eckey->key.public_uncompressed, CRYPTO_ECKEY_PUBLIC_UNCOMPRESSED_SIZE, out);
        break;
    default:
        return URC_EINVALIDARG;
    }
    if (wallyerr != WALLY_OK) {
        return URC_EWALLYINTERNALERROR;
    }
    return URC_OK;
}
