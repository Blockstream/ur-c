
#ifdef WIN32
#include <winsock2.h>
#else
#include <arpa/inet.h>
#endif

#include "urc/crypto_hdkey.h"
#include "urc/tags.h"

#include "internals.h"
#include "macros.h"
#include "utils.h"

urc_error internal_parse_masterkey(CborValue *iter, hd_master_key *out);
urc_error internal_parse_derivedkey(CborValue *iter, hd_derived_key *out);
urc_error internal_parse_coininfo(CborValue *iter, crypto_coininfo *out);
urc_error internal_parse_keypath(CborValue *iter, crypto_keypath *out);
urc_error internal_parse_path_component(CborValue *iter, path_component *out);

urc_error parse_hdkey(size_t size, const uint8_t *buffer, crypto_hdkey *out) {
    CborParser parser;
    CborValue iter;
    CborError err;
    err = cbor_parser_init(buffer, size, cbor_flags, &parser, &iter);
    if (err != CborNoError) {
        urc_error result = {.tag = urc_error_tag_cborinternalerror, .internal.cbor = err};
        return result;
    }
    return internal_parse_hdkey(&iter, out);
}

urc_error internal_parse_hdkey(CborValue *iter, crypto_hdkey *out) {
    urc_error result = {.tag = urc_error_tag_noerror};
    out->type = hdkey_type_na;

    result = internal_parse_masterkey(iter, &out->key.master);
    // NOTE: invered than expected logic
    if (result.tag == urc_error_tag_noerror) {
        out->type = hdkey_type_master;
        goto exit;
    }

    result = internal_parse_derivedkey(iter, &out->key.derived);
    if (result.tag != urc_error_tag_noerror) {
        goto exit;
    }
    out->type = hdkey_type_derived;

exit:
    return result;
}

urc_error internal_parse_masterkey(CborValue *iter, hd_master_key *out) {
    urc_error result = {.tag = urc_error_tag_noerror};

    CHECK_IS_TYPE(iter, map, result, exit);
    CborValue map_item;
    CborError err = cbor_value_enter_container(iter, &map_item);
    {
        result = check_map_key(&map_item, 1);
        if (result.tag != urc_error_tag_noerror) {
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
        if (result.tag != urc_error_tag_noerror) {
            goto exit;
        }
        ADVANCE(&map_item, result, exit);

        CHECK_IS_TYPE(&map_item, byte_string, result, exit);
        result = copy_fixed_size_byte_string(&map_item, (uint8_t *)&out->keydata, CRYPTO_HDKEY_KEYDATA_SIZE);
        if (result.tag != urc_error_tag_noerror) {
            goto exit;
        }
        ADVANCE(&map_item, result, exit);
    }
    {
        result = check_map_key(&map_item, 4);
        if (result.tag != urc_error_tag_noerror) {
            goto exit;
        }
        ADVANCE(&map_item, result, exit);

        CHECK_IS_TYPE(&map_item, byte_string, result, exit);
        result = copy_fixed_size_byte_string(&map_item, (uint8_t *)&out->chaincode, CRYPTO_HDKEY_CHAINCODE_SIZE);
        if (result.tag != urc_error_tag_noerror) {
            goto exit;
        }
        ADVANCE(&map_item, result, exit);
    }

    LEAVE_CONTAINER_SAFELY(iter, &map_item, result, exit);

exit:
    return result;
}

urc_error internal_parse_derivedkey(CborValue *iter, hd_derived_key *out) {
    urc_error result = {.tag = urc_error_tag_noerror};

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
        if (result.tag != urc_error_tag_noerror) {
            goto exit;
        }
        ADVANCE(&map_item, result, exit);

        CHECK_IS_TYPE(&map_item, byte_string, result, exit);
        result = copy_fixed_size_byte_string(&map_item, (uint8_t *)&out->keydata, CRYPTO_HDKEY_KEYDATA_SIZE);
        if (result.tag != urc_error_tag_noerror) {
            goto exit;
        }
        ADVANCE(&map_item, result, exit);
    }
    {
        out->valid_chaincode = false;
        if (is_map_key(&map_item, 4)) {
            ADVANCE(&map_item, result, exit);

            CHECK_IS_TYPE(&map_item, byte_string, result, exit);
            result = copy_fixed_size_byte_string(&map_item, (uint8_t *)&out->chaincode, CRYPTO_HDKEY_CHAINCODE_SIZE);
            if (result.tag != urc_error_tag_noerror) {
                goto exit;
            }
            out->valid_chaincode = true;
            ADVANCE(&map_item, result, exit);
        }
    }
    {
        out->useinfo.network = CRYPTO_COININFO_MAINNET;
        out->useinfo.type = CRYPTO_COININFO_TYPE_BTC;
        if (is_map_key(&map_item, 5)) {
            ADVANCE(&map_item, result, exit);

            result = check_tag(&map_item, urc_urtypes_tags_crypto_coin_info);
            if (result.tag != urc_error_tag_noerror) {
                goto exit;
            }
            ADVANCE(&map_item, result, exit);

            result = internal_parse_coininfo(&map_item, &out->useinfo);
            if (result.tag != urc_error_tag_noerror) {
                goto exit;
            }
        }
    }
    {
        out->origin.components_count = 0;
        out->origin.depth = 0;
        out->origin.source_fingerprint = 0;
        if (is_map_key(&map_item, 6)) {
            ADVANCE(&map_item, result, exit);

            result = check_tag(&map_item, urc_urtypes_tags_crypto_keypath);
            if (result.tag != urc_error_tag_noerror) {
                goto exit;
            }
            ADVANCE(&map_item, result, exit);

            result = internal_parse_keypath(&map_item, &out->origin);
            if (result.tag != urc_error_tag_noerror) {
                goto exit;
            }
        }
    }
    {
        out->children.components_count = 0;
        out->children.depth = 0;
        out->children.source_fingerprint = 0;
        if (is_map_key(&map_item, 7)) {
            ADVANCE(&map_item, result, exit);

            result = check_tag(&map_item, urc_urtypes_tags_crypto_keypath);
            if (result.tag != urc_error_tag_noerror) {
                goto exit;
            }
            ADVANCE(&map_item, result, exit);

            result = internal_parse_keypath(&map_item, &out->children);
            if (result.tag != urc_error_tag_noerror) {
                goto exit;
            }
        }
    }
    {
        out->parent_fingerprint = 0;
        if (is_map_key(&map_item, 8)) {
            ADVANCE(&map_item, result, exit);

            CHECK_IS_TYPE(&map_item, unsigned_integer, result, exit);
            err = cbor_value_get_int(&map_item, (int *)&out->parent_fingerprint);
            CHECK_CBOR_ERROR(err, result, exit);
            ADVANCE(&map_item, result, exit);
        }
    }
    {
        memset(&out->name, 0, NAME_BUFFER_SIZE);
        if (is_map_key(&map_item, 9)) {
            ADVANCE(&map_item, result, exit);

            CHECK_IS_TYPE(&map_item, text_string, result, exit);
            size_t len = NAME_BUFFER_SIZE;
            err = cbor_value_copy_text_string(&map_item, (char *)&out->name, &len, NULL);
            // If the name is too long, truncate it and null-terminate it.
            if (err == CborErrorOutOfMemory) {
                out->name[NAME_BUFFER_SIZE - 1] = '\0';
            } else {
                CHECK_CBOR_ERROR(err, result, exit);
            }
            ADVANCE(&map_item, result, exit);
        }
    }
    {
        memset(&out->note, 0, NOTE_BUFFER_SIZE);
        if (is_map_key(&map_item, 10)) {
            ADVANCE(&map_item, result, exit);

            CHECK_IS_TYPE(&map_item, text_string, result, exit);
            size_t len = NOTE_BUFFER_SIZE;
            err = cbor_value_copy_text_string(&map_item, (char *)&out->note, &len, NULL);
            // If the note is too long, truncate it and null-terminate it.
            if (err == CborErrorOutOfMemory) {
                out->note[NOTE_BUFFER_SIZE - 1] = '\0';
            } else {
                CHECK_CBOR_ERROR(err, result, exit);
            }
            ADVANCE(&map_item, result, exit);
        }
    }
    LEAVE_CONTAINER_SAFELY(iter, &map_item, result, exit);

exit:
    return result;
}

urc_error internal_parse_coininfo(CborValue *iter, crypto_coininfo *out) {
    urc_error result = {.tag = urc_error_tag_noerror};

    CHECK_IS_TYPE(iter, map, result, exit);
    CborValue map_item;
    CborError err = cbor_value_enter_container(iter, &map_item);
    CHECK_CBOR_ERROR(err, result, exit);
    {
        out->type = CRYPTO_COININFO_TYPE_BTC;
        if (is_map_key(&map_item, 1)) {
            ADVANCE(&map_item, result, exit);

            CHECK_IS_TYPE(&map_item, unsigned_integer, result, exit);
            CborError err = cbor_value_get_int(&map_item, (int *)&out->type);
            CHECK_CBOR_ERROR(err, result, exit);
            ADVANCE(&map_item, result, exit);
        }
    }
    {
        out->network = CRYPTO_COININFO_MAINNET;
        if (is_map_key(&map_item, 2)) {
            ADVANCE(&map_item, result, exit);

            CHECK_IS_TYPE(&map_item, integer, result, exit);
            CborError err = cbor_value_get_int(&map_item, (int *)&out->network);
            CHECK_CBOR_ERROR(err, result, exit);
            ADVANCE(&map_item, result, exit);
        }
    }
    LEAVE_CONTAINER_SAFELY(iter, &map_item, result, exit);

exit:
    return result;
}

urc_error internal_parse_keypath(CborValue *iter, crypto_keypath *out) {
    urc_error result = {.tag = urc_error_tag_noerror};
    out->depth = 0;

    CHECK_IS_TYPE(iter, map, result, exit);

    CborValue map_item;
    CborError err;
    err = cbor_value_enter_container(iter, &map_item);
    CHECK_CBOR_ERROR(err, result, exit);
    {
        result = check_map_key(&map_item, 1);
        if (result.tag != urc_error_tag_noerror) {
            goto exit;
        }
        ADVANCE(&map_item, result, exit);

        CHECK_IS_TYPE(&map_item, array, result, exit);
        size_t len = 0;
        err = cbor_value_get_array_length(&map_item, &len);
        CHECK_CBOR_ERROR(err, result, exit);
        // NOTE: every path component is made of two elements
        if (len / 2 > CRYPTO_KEYPATH_MAX_COMPONENTS) {
            result.tag = urc_error_tag_unhandledcase;
            goto exit;
        }
        CborValue comp_item;
        err = cbor_value_enter_container(&map_item, &comp_item);
        CHECK_CBOR_ERROR(err, result, exit);
        int idx = 0;
        while (!cbor_value_at_end(&comp_item) && idx < CRYPTO_KEYPATH_MAX_COMPONENTS) {
            result = internal_parse_path_component(&comp_item, &out->components[idx++]);
            if (result.tag != urc_error_tag_noerror) {
                goto exit;
            }
        }
        out->components_count = idx;

        LEAVE_CONTAINER_SAFELY(&map_item, &comp_item, result, exit);
    }
    {
        out->source_fingerprint = 0;
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
        result.tag = urc_error_tag_unhandledcase;
    }

    LEAVE_CONTAINER_SAFELY(iter, &map_item, result, exit);

exit:
    return result;
}

urc_error internal_parse_index_component(CborValue *iter, child_index_component *out);
urc_error internal_parse_range_component(CborValue *iter, child_range_component *out);
urc_error internal_parse_pair_component(CborValue *iter, child_pair_component *out);

urc_error internal_parse_path_component(CborValue *iter, path_component *out) {
    urc_error result = {.tag = urc_error_tag_noerror};
    out->type = path_component_type_na;

    CborError err;
    if (!cbor_value_is_array(iter)) {
        result = internal_parse_index_component(iter, &out->component.index);
        if (result.tag != urc_error_tag_noerror) {
            goto exit;
        }

        out->type = path_component_type_index;
        goto exit;
    }

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
        ADVANCE(iter, result, exit);
        goto exit;
    }

    result = internal_parse_range_component(iter, &out->component.range);
    // NOTE: invered than expected logic
    if (result.tag == urc_error_tag_noerror) {
        out->type = path_component_type_range;
        goto exit;
    }

    result = internal_parse_pair_component(iter, &out->component.pair);
    // NOTE: invered than expected logic
    if (result.tag == urc_error_tag_noerror) {
        out->type = path_component_type_pair;
        goto exit;
    }

exit:
    return result;
}

urc_error internal_parse_index_component(CborValue *iter, child_index_component *out) {
    urc_error result = {.tag = urc_error_tag_noerror};

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

urc_error internal_parse_range_component(CborValue *iter, child_range_component *out) {
    urc_error result = {.tag = urc_error_tag_noerror};

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

urc_error internal_parse_pair_component(CborValue *iter, child_pair_component *out) {
    urc_error result = {.tag = urc_error_tag_noerror};

    CHECK_IS_TYPE(iter, array, result, exit)

    CborValue item;
    CborError err = cbor_value_enter_container(iter, &item);
    CHECK_CBOR_ERROR(err, result, exit);

    result = internal_parse_index_component(&item, &out->internal);
    if (result.tag != urc_error_tag_noerror) {
        goto exit;
    }

    result = internal_parse_index_component(&item, &out->external);
    if (result.tag != urc_error_tag_noerror) {
        goto exit;
    }

    LEAVE_CONTAINER_SAFELY(iter, &item, result, exit);

exit:
    return result;
}

bool bip32_serialize(const crypto_hdkey *hdkey, uint8_t out[BIP32_SERIALIZED_LEN]) {
    size_t cursor = 0;

    uint32_t *version = (uint32_t *)&out[cursor]; // 0 - 3
    cursor += sizeof(uint32_t);
    switch (hdkey->type) {
    case hdkey_type_master:
        *version = htonl(0x0488ADE4);
        break;
    case hdkey_type_derived:
        switch (hdkey->key.derived.useinfo.network) {
        case CRYPTO_COININFO_MAINNET:
            if (hdkey->key.derived.is_private) {
                *version = htonl(0x0488ADE4);
            } else {
                *version = htonl(0x0488B21E);
            }
            break;
        case CRYPTO_COININFO_TESTNET:
            if (hdkey->key.derived.is_private) {
                *version = htonl(0x04358394);
            } else {
                *version = htonl(0x043587CF);
            }
            break;
        default:
            return false;
        }
        break;
    default:
        return false;
    }

    uint8_t *depth = (uint8_t *)&out[cursor]; // 4
    cursor += sizeof(uint8_t);
    switch (hdkey->type) {
    case hdkey_type_master:
        *depth = 0x00;
        break;
    case hdkey_type_derived:
        *depth = hdkey->key.derived.origin.components_count;
        for (size_t idx = 0; idx < hdkey->key.derived.children.components_count; idx++) {
            if (hdkey->key.derived.children.components[idx].type == path_component_type_index) {
                *depth += 1;
            }
        }
        break;
    default:
        return false;
    }

    uint32_t *parent_fingerprint = (uint32_t *)&out[cursor]; // 5 - 8
    cursor += sizeof(uint32_t);
    switch (hdkey->type) {
    case hdkey_type_master:
        *parent_fingerprint = 0;
        break;
    case hdkey_type_derived:
        *parent_fingerprint = htonl(hdkey->key.derived.parent_fingerprint);
        break;
    default:
        return false;
    }

    uint32_t *child_number = (uint32_t *)&out[cursor]; // 9 - 12
    cursor += sizeof(uint32_t);
    switch (hdkey->type) {
    case hdkey_type_master:
        *child_number = 0;
        break;
    case hdkey_type_derived:
        if (hdkey->key.derived.origin.components_count == 0) {
            *child_number = 0;
        } else {
            const path_component *last_origincomponent =
                &hdkey->key.derived.origin.components[hdkey->key.derived.origin.components_count - 1];
            switch (last_origincomponent->type) {
            case path_component_type_index:
                *child_number = htonl(last_origincomponent->component.index.index +
                                      0x80000000 * last_origincomponent->component.index.is_hardened);
                break;
            default:
                return false;
            }
        }
        if (hdkey->key.derived.children.components_count == 0) {
            break;
        }
        const path_component *last_childcomponent =
            &hdkey->key.derived.children.components[hdkey->key.derived.children.components_count - 1];
        switch (last_childcomponent->type) {
        case path_component_type_wildcard:
            *child_number = htonl(0xfffffffe);
            break;
        default:
            return false;
        }
        break;
    default:
        return false;
    }

    uint8_t(*chain_code)[CRYPTO_HDKEY_CHAINCODE_SIZE] = (uint8_t(*)[CRYPTO_HDKEY_CHAINCODE_SIZE]) & out[cursor]; // 13 - 44
    cursor += CRYPTO_HDKEY_CHAINCODE_SIZE;
    switch (hdkey->type) {
    case hdkey_type_master:
        memcpy(chain_code, hdkey->key.master.chaincode, CRYPTO_HDKEY_CHAINCODE_SIZE);
        break;
    case hdkey_type_derived:
        memcpy(chain_code, hdkey->key.derived.chaincode, CRYPTO_HDKEY_CHAINCODE_SIZE);
        break;
    default:
        return -1;
    }

    uint8_t(*key_data)[CRYPTO_HDKEY_KEYDATA_SIZE] = (uint8_t(*)[CRYPTO_HDKEY_KEYDATA_SIZE]) & out[cursor]; // 45 - 77
    cursor += CRYPTO_HDKEY_KEYDATA_SIZE;
    switch (hdkey->type) {
    case hdkey_type_master:
        memcpy(key_data, hdkey->key.master.keydata, CRYPTO_HDKEY_KEYDATA_SIZE);
        break;
    case hdkey_type_derived:
        memcpy(key_data, hdkey->key.derived.keydata, CRYPTO_HDKEY_KEYDATA_SIZE);
        break;
    default:
        return -1;
    }

    return true;
}

int format_keyorigin(const crypto_hdkey *hdkey, size_t size, char *out) {
    int total_len = 0;
    {
        uint32_t fpr = 0;
        switch (hdkey->type) {
        case hdkey_type_master:
            fpr = 0;
            break;
        case hdkey_type_derived:
            fpr = hdkey->key.derived.origin.source_fingerprint;
            if (fpr == 0) {
                fpr = hdkey->key.derived.parent_fingerprint;
            }
            break;
        default:
            return -1;
        }
        int len = snprintf(out, size, "[%08x", fpr);
        total_len += len;
        // either an error or an out-of-space
        if (len < 0 || (size_t)total_len >= size) {
            return len < 0 ? len : total_len;
        }
    }
    {
        const path_component *comps = NULL;
        size_t comps_count = 0;
        switch (hdkey->type) {
        case hdkey_type_master:
            // no components
            break;
        case hdkey_type_derived:
            comps = hdkey->key.derived.origin.components;
            comps_count = hdkey->key.derived.origin.components_count;
            break;
        default:
            return -1;
        }
        for (size_t idx = 0; idx < comps_count; idx++) {
            const path_component *comp = &(comps[idx]);
            int len = 0;
            switch (comp->type) {
            case path_component_type_index:
                len = snprintf(&out[total_len], size - total_len, "/%d%s", comp->component.index.index,
                               comp->component.index.is_hardened ? "'" : "");
                break;
            default:
                return -1;
            }
            total_len += len;
            // either an error or an out-of-space
            if (len < 0 || (size_t)total_len >= size) {
                return len < 0 ? len : total_len;
            }
        }
    }
    int len = snprintf(&out[total_len], size - total_len, "]");
    if (len < 0) {
        return len;
    }
    total_len += len;
    return total_len;
}

int format_keyderivationpath(const crypto_hdkey *hdkey, size_t size, char *out) {
    switch (hdkey->type) {
    case hdkey_type_master:
        return 0;
    case hdkey_type_na:
        return -1;
    default:
        break;
    }

    int total_len = 0;
    for (size_t idx = 0; idx < hdkey->key.derived.children.components_count; idx++) {
        const path_component *comp = &hdkey->key.derived.children.components[idx];
        int len = 0;
        switch (comp->type) {
        case path_component_type_index:
            if (comp->component.index.is_hardened) {
                len = snprintf(&out[total_len], size - total_len, "/%d'", comp->component.index.index);
            } else {
                len = snprintf(&out[total_len], size - total_len, "/%d", comp->component.index.index);
            }
            break;
        case path_component_type_wildcard:
            len = snprintf(&out[total_len], size - total_len, "/*");
            break;
        default:
            return -1;
        }
        total_len += len;
        if (len < 0 || (size_t)total_len >= size) {
            return len < 0 ? len : total_len;
        }
    }

    return total_len;
}
