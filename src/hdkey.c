
#include "tinycbor/cbor.h"

#include "bcr/crypto_hdkey.h"
#include "bcr/error.h"

#include "macros.h"
#include "utils.h"
#include <stdlib.h>

bcr_error internal_parse_hdkey(CborValue *iter, crypto_hdkey *out);
bcr_error internal_parse_masterkey(CborValue *iter, hd_master_key *out);
bcr_error internal_parse_derivedkey(CborValue *iter, hd_derived_key *out);
bcr_error internal_parse_keypath(CborValue *iter, crypto_keypath *out);
bcr_error internal_parse_path_component(CborValue *iter, path_component *out);

bcr_error parse_hdkey(size_t size, const uint8_t buffer[size], crypto_hdkey *out) {
    CborParser parser;
    CborValue iter;
    CborError err;
    err = cbor_parser_init(buffer, size, cbor_flags, &parser, &iter);
    if (err != CborNoError) {
        bcr_error result = {.tag = bcr_error_tag_cborinternalerror, .internal.cbor = err};
        return result;
    }
    return internal_parse_hdkey(&iter, out);
}

bcr_error internal_parse_hdkey(CborValue *iter, crypto_hdkey *out) {
    out->type = hdkey_type_na;
    bcr_error result = {.tag = bcr_error_tag_noerror};

    result = internal_parse_masterkey(iter, &out->key.master);
    // NOTE: invered than expected logic
    if (result.tag == bcr_error_tag_noerror) {
        out->type = hdkey_type_master;
        goto exit;
    }

    result = internal_parse_derivedkey(iter, &out->key.derived);
    if (result.tag != bcr_error_tag_noerror) {
        goto exit;
    }
    out->type = hdkey_type_derived;

exit:
    return result;
}

bcr_error internal_parse_masterkey(CborValue *iter, hd_master_key *out) {
    bcr_error result = {.tag = bcr_error_tag_noerror};

    CHECK_IS_TYPE(iter, map, result, exit);
    CborValue map_item;
    CborError err = cbor_value_enter_container(iter, &map_item);
    {
        result = check_map_key(&map_item, 1);
        if (result.tag != bcr_error_tag_noerror) {
            goto exit;
        }
        ADVANCE(&map_item, result, exit);

        CHECK_IS_TYPE(&map_item, boolean, result, exit);
        err = cbor_value_get_boolean(&map_item, &out->is_master);
        CHECK_CBOR_ERROR(err, result, exit);
        ADVANCE(&map_item, result, exit);
    }
    {
        result = check_map_key(&map_item, 3);
        if (result.tag != bcr_error_tag_noerror) {
            goto exit;
        }
        ADVANCE(&map_item, result, exit);

        CHECK_IS_TYPE(&map_item, byte_string, result, exit);
        result = copy_fixed_size_byte_string(&map_item, CRYPTO_HDKEY_KEYDATA_SIZE, (uint8_t *)&out->keydata);
        if (result.tag != bcr_error_tag_noerror) {
            goto exit;
        }
        ADVANCE(&map_item, result, exit);
    }
    {
        result = check_map_key(&map_item, 4);
        if (result.tag != bcr_error_tag_noerror) {
            goto exit;
        }
        ADVANCE(&map_item, result, exit);

        CHECK_IS_TYPE(&map_item, byte_string, result, exit);
        result = copy_fixed_size_byte_string(&map_item, CRYPTO_HDKEY_CHAINCODE_SIZE, (uint8_t *)&out->chaincode);
        if (result.tag != bcr_error_tag_noerror) {
            goto exit;
        }
        ADVANCE(&map_item, result, exit);
    }

    LEAVE_CONTAINER_SAFELY(iter, &map_item, result, exit);

exit:
    return result;
}

bcr_error internal_parse_derivedkey(CborValue *iter, hd_derived_key *out) {
    bcr_error result = {.tag = bcr_error_tag_noerror};
    CHECK_IS_TYPE(iter, map, result, exit);
    CborValue map_item;
    CborError err = cbor_value_enter_container(iter, &map_item);
    {
        out->is_private = false;
        if (is_map_key(&map_item, 2)) {
            ADVANCE(&map_item, result, exit);

            CHECK_IS_TYPE(&map_item, boolean, result, exit);
            err = cbor_value_get_boolean(&map_item, &out->is_private);
            CHECK_CBOR_ERROR(err, result, exit);
            ADVANCE(&map_item, result, exit);
        }
    }
    {
        result = check_map_key(&map_item, 3);
        if (result.tag != bcr_error_tag_noerror) {
            goto exit;
        }
        ADVANCE(&map_item, result, exit);

        CHECK_IS_TYPE(&map_item, byte_string, result, exit);
        result = copy_fixed_size_byte_string(&map_item, CRYPTO_HDKEY_KEYDATA_SIZE, (uint8_t *)&out->keydata);
        if (result.tag != bcr_error_tag_noerror) {
            goto exit;
        }
        ADVANCE(&map_item, result, exit);
    }
    {
        out->valid_chaincode = false;
        if (is_map_key(&map_item, 4)) {
            ADVANCE(&map_item, result, exit);

            CHECK_IS_TYPE(&map_item, byte_string, result, exit);
            result = copy_fixed_size_byte_string(&map_item, CRYPTO_HDKEY_CHAINCODE_SIZE, (uint8_t *)&out->chaincode);
            if (result.tag != bcr_error_tag_noerror) {
                goto exit;
            }
            out->valid_chaincode = true;
            ADVANCE(&map_item, result, exit);
        }
    }

exit:
    return result;
}

bcr_error internal_parse_coininfo(CborValue *iter, crypto_coininfo *out) {
    bcr_error result = {.tag = bcr_error_tag_noerror};
    out->type = 0;
    CHECK_IS_TYPE(iter, boolean, result, exit);

exit:
    return result;
}

bcr_error internal_parse_keypath(CborValue *iter, crypto_keypath *out) {
    bcr_error result = {.tag = bcr_error_tag_noerror};
    out->depth = 0;

    CHECK_IS_TYPE(iter, map, result, exit);

    CborValue map_item;
    CborError err;
    err = cbor_value_enter_container(iter, &map_item);
    CHECK_CBOR_ERROR(err, result, exit);
    {
        result = check_map_key(&map_item, 1);
        if (result.tag != bcr_error_tag_noerror) {
            goto exit;
        }
        ADVANCE(&map_item, result, exit);

        CHECK_IS_TYPE(&map_item, array, result, exit);
        size_t len = 0;
        err = cbor_value_get_array_length(&map_item, &len);
        CHECK_CBOR_ERROR(err, result, exit);
        if (len > CRYPTO_KEYPATH_MAX_COMPONENTS) {
            result.tag = bcr_error_tag_unhandledcase;
            goto exit;
        }
        CborValue comps_item;
        err = cbor_value_enter_container(&map_item, &comps_item);
        CHECK_CBOR_ERROR(err, result, exit);
        for (size_t idx = 0; idx < len; idx++) {
            result = internal_parse_path_component(&comps_item, &out->components[idx]);
            if (result.tag != bcr_error_tag_noerror) {
                goto exit;
            }
        }
        out->components_count = len;

        LEAVE_CONTAINER_SAFELY(iter, &comps_item, result, exit);
    }
    {
        if (is_map_key(&map_item, 2)) {
            ADVANCE(&map_item, result, exit);

            CHECK_IS_TYPE(&map_item, unsigned_integer, result, exit);
            err = cbor_value_get_int(&map_item, (int *)&out->source_fingerprint);
            CHECK_CBOR_ERROR(err, result, exit);

            ADVANCE(&map_item, result, exit);
        }
    }
    {
        if (is_map_key(&map_item, 3)) {
            ADVANCE(&map_item, result, exit);

            CHECK_IS_TYPE(&map_item, unsigned_integer, result, exit);
            int val;
            err = cbor_value_get_int(&map_item, &val);
            CHECK_CBOR_ERROR(err, result, exit);
            out->depth = val;

            ADVANCE(&map_item, result, exit);
        }
    }

    if (out->components_count == 0 && out->source_fingerprint == 0) {
        result.tag = bcr_error_tag_unhandledcase;
    }

exit:
    return result;
}

bcr_error internal_parse_index_component(CborValue *iter, child_index_component *out);
bcr_error internal_parse_range_component(CborValue *iter, child_range_component *out);
bcr_error internal_parse_pair_component(CborValue *iter, child_pair_component *out);

bcr_error internal_parse_path_component(CborValue *iter, path_component *out) {
    bcr_error result = {.tag = bcr_error_tag_noerror};
    out->type = path_component_type_na;

    CborError err;
    if (!cbor_value_is_array(iter)) {
        result = internal_parse_index_component(iter, &out->component.index);
        if (result.tag != bcr_error_tag_noerror) {
            goto exit;
        }

        out->type = path_component_type_index;
        goto exit;
    }

    // WARNING: untested territory
    CHECK_IS_TYPE(iter, array, result, exit);
    size_t len;
    err = cbor_value_get_array_length(iter, &len);
    CHECK_CBOR_ERROR(err, result, exit);

    if (len == 0) {
        // wildcard-component
        ADVANCE(iter, result, exit); // skip the empty array

        CHECK_IS_TYPE(iter, boolean, result, exit);
        err = cbor_value_get_boolean(iter, &out->component.wildcard.is_hardened);
        CHECK_CBOR_ERROR(err, result, exit);

        out->type = path_component_type_wildcard;
        goto exit;
    }

    result = internal_parse_range_component(iter, &out->component.range);
    // NOTE: invered than expected logic
    if (result.tag == bcr_error_tag_noerror) {
        out->type = path_component_type_range;
        goto exit;
    }

    result = internal_parse_pair_component(iter, &out->component.pair);
    // NOTE: invered than expected logic
    if (result.tag == bcr_error_tag_noerror) {
        out->type = path_component_type_pair;
        goto exit;
    }

exit:
    return result;
}

bcr_error internal_parse_index_component(CborValue *iter, child_index_component *out) {
    bcr_error result = {.tag = bcr_error_tag_noerror};

    CHECK_IS_TYPE(iter, unsigned_integer, result, exit);
    CborError err = cbor_value_get_int(iter, (int *)&out->index);
    CHECK_CBOR_ERROR(err, result, exit);

    ADVANCE(iter, result, exit);

    CHECK_IS_TYPE(iter, boolean, result, exit);
    err = cbor_value_get_boolean(iter, &out->is_hardened);
    CHECK_CBOR_ERROR(err, result, exit);

    ADVANCE(iter, result, exit);

exit:
    return result;
}

bcr_error internal_parse_range_component(CborValue *iter, child_range_component *out) {
    bcr_error result = {.tag = bcr_error_tag_noerror};

    CHECK_IS_TYPE(iter, array, result, exit);

    CborValue item;
    CborError err = cbor_value_enter_container(iter, &item);
    CHECK_CBOR_ERROR(err, result, exit);

    CHECK_IS_TYPE(&item, unsigned_integer, result, exit);
    err = cbor_value_get_int(&item, (int *)&out->low);
    CHECK_CBOR_ERROR(err, result, exit);

    ADVANCE(&item, result, exit);

    CHECK_IS_TYPE(&item, unsigned_integer, result, exit);
    err = cbor_value_get_int(&item, (int *)&out->high);
    CHECK_CBOR_ERROR(err, result, exit);

    LEAVE_CONTAINER_SAFELY(iter, &item, result, exit);

    CHECK_IS_TYPE(iter, boolean, result, exit);
    err = cbor_value_get_boolean(iter, &out->is_hardened);
    CHECK_CBOR_ERROR(err, result, exit);

    ADVANCE(iter, result, exit);

exit:
    return result;
}

bcr_error internal_parse_pair_component(CborValue *iter, child_pair_component *out) {
    bcr_error result = {.tag = bcr_error_tag_noerror};

    CHECK_IS_TYPE(iter, array, result, exit)

    CborValue item;
    CborError err = cbor_value_enter_container(iter, &item);
    CHECK_CBOR_ERROR(err, result, exit);

    result = internal_parse_index_component(&item, &out->internal);
    if (result.tag != bcr_error_tag_noerror) {
        goto exit;
    }

    result = internal_parse_index_component(&item, &out->external);
    if (result.tag != bcr_error_tag_noerror) {
        goto exit;
    }

    LEAVE_CONTAINER_SAFELY(iter, &item, result, exit);

exit:
    return result;
}
