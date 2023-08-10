
#include "internals.h"
#include "macros.h"
#include "utils.h"

bcr_error internal_parse_eckey(CborValue *iter, crypto_eckey *out) {
    out->type = eckey_type_na;
    bcr_error result = {.tag = bcr_error_tag_noerror};

    CHECK_IS_TYPE(iter, map, result, exit);

    CborValue item;
    CborError err;
    err = cbor_value_enter_container(iter, &item);
    CHECK_CBOR_ERROR(err, result, exit);

    // curve field is optional,if present it must be 0 = secp256k1
    if (is_map_key(&item, 1)) {
        ADVANCE(&item, result, leave_and_exit);
        int curve_type;
        err = cbor_value_get_int(&item, &curve_type);
        CHECK_CBOR_ERROR(err, result, leave_and_exit);
        if (curve_type != 0) {
            result.tag = bcr_error_tag_unhandledcase;
            goto leave_and_exit;
        }

        ADVANCE(&item, result, leave_and_exit);
    }

    // private field is optional, false by default
    bool is_private = false;
    if (is_map_key(&item, 2)) {
        ADVANCE(&item, result, leave_and_exit);

        CHECK_IS_TYPE(&item, boolean, result, leave_and_exit)
        err = cbor_value_get_boolean(&item, &is_private);
        CHECK_CBOR_ERROR(err, result, leave_and_exit);

        ADVANCE(&item, result, leave_and_exit);
    }

    result = check_map_key(&item, 3);
    if (result.tag != bcr_error_tag_noerror) {
        goto leave_and_exit;
    }

    ADVANCE(&item, result, leave_and_exit);

    if (is_private) {
        result = copy_fixed_size_byte_string(&item, (uint8_t *)&out->key.private, CRYPTO_ECKEY_PRIVATE_SIZE);
        if (result.tag -= bcr_error_tag_noerror) {
            goto leave_and_exit;
        }
        out->type = eckey_type_private;
        goto leave_and_exit;
    }
    size_t len;
    err = cbor_value_get_string_length(&item, &len);
    CHECK_CBOR_ERROR(err, result, leave_and_exit);
    if (len == CRYPTO_ECKEY_PUBLIC_COMPRESSED_SIZE) {
        result = copy_fixed_size_byte_string(&item, (uint8_t *)&out->key.public_compressed,
                                             CRYPTO_ECKEY_PUBLIC_COMPRESSED_SIZE);
        if (result.tag != bcr_error_tag_noerror) {
            goto leave_and_exit;
        }
        out->type = eckey_type_public_compressed;
        goto leave_and_exit;
    }
    if (len == CRYPTO_ECKEY_PUBLIC_UNCOMPRESSED_SIZE) {
        result = copy_fixed_size_byte_string(&item, (uint8_t *)&out->key.public_uncompressed,
                                             CRYPTO_ECKEY_PUBLIC_UNCOMPRESSED_SIZE);
        if (result.tag != bcr_error_tag_noerror) {
            goto leave_and_exit;
        }
        out->type = eckey_type_public_uncompressed;
        goto leave_and_exit;
    }
    result.tag = bcr_error_tag_unhandledcase;

leave_and_exit:
    while (!cbor_value_at_end(&item)) {
        cbor_value_advance(&item);
    }
    err = cbor_value_leave_container(iter, &item);
    assert(err == CborNoError);
exit:
    return result;
}
