
#include "wally_core.h"

#include "urc/core.h"
#include "urc/crypto_account.h"
#include "urc/tags.h"

#include "internals.h"
#include "macros.h"
#include "utils.h"

int urc_crypto_account_deserialize_impl(CborValue *iter, crypto_account *out);

int urc_crypto_account_deserialize(const uint8_t *buffer, size_t len, crypto_account *out)
{
    CborParser parser;
    CborValue iter;
    CborError err;
    err = cbor_parser_init(buffer, len, cbor_flags, &parser, &iter);
    if (err != CborNoError) {
        return URC_ECBORINTERNALERROR;
    }
    return urc_crypto_account_deserialize_impl(&iter, out);
}

int urc_crypto_account_deserialize_impl(CborValue *iter, crypto_account *out)
{
    int result = URC_OK;
    out->descriptors_count = 0;
    bool taproot_found = false;

    CHECK_IS_TYPE(iter, map, result, exit);
    CborValue map_item;
    CborError err = cbor_value_enter_container(iter, &map_item);
    CHECK_CBOR_ERROR(err, result, exit);

    result = check_map_key(&map_item, 1);
    if (result != URC_OK) {
        goto exit;
    }
    ADVANCE(&map_item, result, exit);
    CHECK_IS_TYPE(&map_item, unsigned_integer, result, exit);
    err = cbor_value_get_int(&map_item, (int *)&out->master_fingerprint);
    CHECK_CBOR_ERROR(err, result, exit);
    ADVANCE(&map_item, result, exit);

    result = check_map_key(&map_item, 2);
    if (result != URC_OK) {
        goto exit;
    }
    ADVANCE(&map_item, result, exit);
    CHECK_IS_TYPE(&map_item, array, result, exit);
    size_t len;
    err = cbor_value_get_array_length(&map_item, &len);
    CHECK_CBOR_ERROR(err, result, exit);
    CborValue array_item;
    err = cbor_value_enter_container(&map_item, &array_item);
    CHECK_CBOR_ERROR(err, result, exit);

    int limit = DESCRIPTORS_MAX_SIZE > len ? len : DESCRIPTORS_MAX_SIZE;
    int item_idx = 0;
    for (int parser_idx = 0; parser_idx < limit; parser_idx++) {
        result = check_tag(&array_item, urc_urtypes_tags_crypto_output);
        if (result != URC_OK) {
            goto exit;
        }
        ADVANCE(&array_item, result, exit);
        result = urc_crypto_output_deserialize_impl(&array_item, &out->descriptors[item_idx++]);
        // // WARNING: taproot not yet supported, skipping it
        if (result == URC_ETAPROOTNOTSUPPORTED) {
            taproot_found = true;
            item_idx--;
            result = URC_OK;
            while (cbor_value_at_end(&array_item) == false) {
                if (cbor_value_is_tag(&array_item)) {
                    CborTag tmp_tag;
                    err = cbor_value_get_tag(&array_item, &tmp_tag);
                    CHECK_CBOR_ERROR(err, result, exit);
                    if (tmp_tag == urc_urtypes_tags_crypto_output) {
                        break;
                    }
                }
                ADVANCE(&array_item, result, exit);
            }
        } else if (result != URC_OK) {
            goto exit;
        }
    }
    out->descriptors_count = item_idx;
    LEAVE_CONTAINER_SAFELY(&map_item, &array_item, result, exit);

    LEAVE_CONTAINER_SAFELY(iter, &map_item, result, exit);

exit:
    if (result == URC_OK && taproot_found) {
        result = URC_ETAPROOTNOTSUPPORTED;
    }
    return result;
}

int urc_crypto_account_format(const crypto_account *account, urc_crypto_output_format_mode mode, char **out[])
{
    if (!account || !out) {
        return URC_EINVALIDARG;
    }

    size_t array_size = sizeof(char *) * (account->descriptors_count + 1);
    *out = wally_malloc(array_size);
    if (!*out) {
        return URC_ENOMEM;
    }
    (*out)[account->descriptors_count] = NULL;

    for (size_t idx = 0; idx < account->descriptors_count; idx++) {
        int result = urc_crypto_output_format(&account->descriptors[idx], mode, &(*out)[idx]);
        if (result != URC_OK) {
            urc_string_array_free(*out);
            *out = NULL;
            return result;
        }
    }
    return URC_OK;
}
