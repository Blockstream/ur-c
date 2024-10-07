
#include "urc/core.h"
#include "urc/error.h"
#ifdef WIN32
#include <winsock2.h>
#else
#include <arpa/inet.h>
#endif

#include "wally_bip32.h"
#include "wally_core.h"

#include "urc/crypto_hdkey.h"
#include "urc/tags.h"

#include "internals.h"
#include "macros.h"
#include "utils.h"

int urc_crypto_hdkey_masterkey_parse(CborValue *iter, hd_master_key *out);
int urc_crypto_hdkey_derivedkey_parse(CborValue *iter, hd_derived_key *out);
int urc_crypto_hdkey_coininfo_parse(CborValue *iter, crypto_coininfo *out);
int urc_crypto_hdkey_keypath_parse(CborValue *iter, crypto_keypath *out);
int urc_crypto_hdkey_pathcomponent_parse(CborValue *iter, path_component *out);

int urc_crypto_hdkey_deserialize(const uint8_t *buffer, size_t len, crypto_hdkey *out)
{
    CborParser parser;
    CborValue iter;
    CborError err;
    err = cbor_parser_init(buffer, len, cbor_flags, &parser, &iter);
    if (err != CborNoError) {
        return URC_ECBORINTERNALERROR;
    }
    return urc_crypto_hdkey_deserialize_impl(&iter, out);
}

int urc_crypto_hdkey_deserialize_impl(CborValue *iter, crypto_hdkey *out)
{
    int result = URC_OK;
    out->type = hdkey_type_na;

    result = urc_crypto_hdkey_masterkey_parse(iter, &out->key.master);
    // NOTE: invered than expected logic
    if (result == URC_OK) {
        out->type = hdkey_type_master;
        goto exit;
    }

    result = urc_crypto_hdkey_derivedkey_parse(iter, &out->key.derived);
    if (result != URC_OK) {
        goto exit;
    }
    out->type = hdkey_type_derived;

exit:
    return result;
}

int urc_crypto_hdkey_masterkey_parse(CborValue *iter, hd_master_key *out)
{
    int result = URC_OK;

    CHECK_IS_TYPE(iter, map, result, exit);
    CborValue map_item;
    CborError err = cbor_value_enter_container(iter, &map_item);

    result = check_map_key(&map_item, 1);
    if (result != URC_OK) {
        goto exit;
    }
    ADVANCE(&map_item, result, exit);
    CHECK_IS_TYPE(&map_item, boolean, result, exit);
    err = cbor_value_get_boolean(&map_item, &out->is_master);
    CHECK_CBOR_ERROR(err, result, exit);
    ADVANCE(&map_item, result, exit);

    result = check_map_key(&map_item, 3);
    if (result != URC_OK) {
        goto exit;
    }
    ADVANCE(&map_item, result, exit);
    CHECK_IS_TYPE(&map_item, byte_string, result, exit);
    result = copy_fixed_size_byte_string(&map_item, (uint8_t *)&out->keydata, CRYPTO_HDKEY_KEYDATA_SIZE);
    if (result != URC_OK) {
        goto exit;
    }
    ADVANCE(&map_item, result, exit);

    result = check_map_key(&map_item, 4);
    if (result != URC_OK) {
        goto exit;
    }
    ADVANCE(&map_item, result, exit);
    CHECK_IS_TYPE(&map_item, byte_string, result, exit);
    result = copy_fixed_size_byte_string(&map_item, (uint8_t *)&out->chaincode, CRYPTO_HDKEY_CHAINCODE_SIZE);
    if (result != URC_OK) {
        goto exit;
    }
    ADVANCE(&map_item, result, exit);

    LEAVE_CONTAINER_SAFELY(iter, &map_item, result, exit);

exit:
    return result;
}

int urc_crypto_hdkey_derivedkey_parse(CborValue *iter, hd_derived_key *out)
{
    int result = URC_OK;

    CHECK_IS_TYPE(iter, map, result, exit);
    CborValue map_item;
    CborError err = cbor_value_enter_container(iter, &map_item);

    out->is_private = false;
    if (is_map_key(&map_item, 2)) {
        ADVANCE(&map_item, result, exit);
        CHECK_IS_TYPE(&map_item, boolean, result, exit);
        err = cbor_value_get_boolean(&map_item, &out->is_private);
        CHECK_CBOR_ERROR(err, result, exit);
        ADVANCE(&map_item, result, exit);
    }

    result = check_map_key(&map_item, 3);
    if (result != URC_OK) {
        goto exit;
    }
    ADVANCE(&map_item, result, exit);
    CHECK_IS_TYPE(&map_item, byte_string, result, exit);
    result = copy_fixed_size_byte_string(&map_item, (uint8_t *)&out->keydata, CRYPTO_HDKEY_KEYDATA_SIZE);
    if (result != URC_OK) {
        goto exit;
    }
    ADVANCE(&map_item, result, exit);

    out->valid_chaincode = false;
    if (is_map_key(&map_item, 4)) {
        ADVANCE(&map_item, result, exit);

        CHECK_IS_TYPE(&map_item, byte_string, result, exit);
        result = copy_fixed_size_byte_string(&map_item, (uint8_t *)&out->chaincode, CRYPTO_HDKEY_CHAINCODE_SIZE);
        if (result != URC_OK) {
            goto exit;
        }
        out->valid_chaincode = true;
        ADVANCE(&map_item, result, exit);
    }

    out->useinfo.network = CRYPTO_COININFO_MAINNET;
    out->useinfo.type = CRYPTO_COININFO_TYPE_BTC;
    if (is_map_key(&map_item, 5)) {
        ADVANCE(&map_item, result, exit);
        result = check_tag(&map_item, urc_urtypes_tags_crypto_coin_info);
        if (result != URC_OK) {
            goto exit;
        }
        ADVANCE(&map_item, result, exit);
        result = urc_crypto_hdkey_coininfo_parse(&map_item, &out->useinfo);
        if (result != URC_OK) {
            goto exit;
        }
    }

    out->origin.components_count = 0;
    out->origin.depth = 0;
    out->origin.source_fingerprint = 0;
    if (is_map_key(&map_item, 6)) {
        ADVANCE(&map_item, result, exit);
        result = check_tag(&map_item, urc_urtypes_tags_crypto_keypath);
        if (result != URC_OK) {
            goto exit;
        }
        ADVANCE(&map_item, result, exit);
        result = urc_crypto_hdkey_keypath_parse(&map_item, &out->origin);
        if (result != URC_OK) {
            goto exit;
        }
    }

    out->children.components_count = 0;
    out->children.depth = 0;
    out->children.source_fingerprint = 0;
    if (is_map_key(&map_item, 7)) {
        ADVANCE(&map_item, result, exit);
        result = check_tag(&map_item, urc_urtypes_tags_crypto_keypath);
        if (result != URC_OK) {
            goto exit;
        }
        ADVANCE(&map_item, result, exit);
        result = urc_crypto_hdkey_keypath_parse(&map_item, &out->children);
        if (result != URC_OK) {
            goto exit;
        }
    }

    out->parent_fingerprint = 0;
    if (is_map_key(&map_item, 8)) {
        ADVANCE(&map_item, result, exit);
        CHECK_IS_TYPE(&map_item, unsigned_integer, result, exit);
        err = cbor_value_get_int(&map_item, (int *)&out->parent_fingerprint);
        CHECK_CBOR_ERROR(err, result, exit);
        ADVANCE(&map_item, result, exit);
    }

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

    LEAVE_CONTAINER_SAFELY(iter, &map_item, result, exit);

exit:
    return result;
}

int urc_crypto_hdkey_coininfo_parse(CborValue *iter, crypto_coininfo *out)
{
    int result = URC_OK;

    CHECK_IS_TYPE(iter, map, result, exit);
    CborValue map_item;
    CborError err = cbor_value_enter_container(iter, &map_item);
    CHECK_CBOR_ERROR(err, result, exit);

    out->type = CRYPTO_COININFO_TYPE_BTC;
    if (is_map_key(&map_item, 1)) {
        ADVANCE(&map_item, result, exit);
        CHECK_IS_TYPE(&map_item, unsigned_integer, result, exit);
        CborError err = cbor_value_get_int(&map_item, (int *)&out->type);
        CHECK_CBOR_ERROR(err, result, exit);
        ADVANCE(&map_item, result, exit);
    }

    out->network = CRYPTO_COININFO_MAINNET;
    if (is_map_key(&map_item, 2)) {
        ADVANCE(&map_item, result, exit);
        CHECK_IS_TYPE(&map_item, integer, result, exit);
        CborError err = cbor_value_get_int(&map_item, (int *)&out->network);
        CHECK_CBOR_ERROR(err, result, exit);
        ADVANCE(&map_item, result, exit);
    }

    LEAVE_CONTAINER_SAFELY(iter, &map_item, result, exit);

exit:
    return result;
}

int urc_crypto_hdkey_keypath_parse(CborValue *iter, crypto_keypath *out)
{
    int result = URC_OK;
    out->depth = 0;

    CHECK_IS_TYPE(iter, map, result, exit);

    CborValue map_item;
    CborError err;
    err = cbor_value_enter_container(iter, &map_item);
    CHECK_CBOR_ERROR(err, result, exit);

    result = check_map_key(&map_item, 1);
    if (result != URC_OK) {
        goto exit;
    }
    ADVANCE(&map_item, result, exit);
    CHECK_IS_TYPE(&map_item, array, result, exit);
    size_t len = 0;
    err = cbor_value_get_array_length(&map_item, &len);
    CHECK_CBOR_ERROR(err, result, exit);
    // NOTE: every path component is made of two elements
    if (len / 2 > CRYPTO_KEYPATH_MAX_COMPONENTS) {
        result = URC_EUNHANDLEDCASE;
        goto exit;
    }
    CborValue comp_item;
    err = cbor_value_enter_container(&map_item, &comp_item);
    CHECK_CBOR_ERROR(err, result, exit);
    int idx = 0;
    while (!cbor_value_at_end(&comp_item) && idx < CRYPTO_KEYPATH_MAX_COMPONENTS) {
        result = urc_crypto_hdkey_pathcomponent_parse(&comp_item, &out->components[idx++]);
        if (result != URC_OK) {
            goto exit;
        }
    }
    out->components_count = idx;
    LEAVE_CONTAINER_SAFELY(&map_item, &comp_item, result, exit);

    out->source_fingerprint = 0;
    if (is_map_key(&map_item, 2)) {
        ADVANCE(&map_item, result, exit);
        CHECK_IS_TYPE(&map_item, unsigned_integer, result, exit);
        err = cbor_value_get_int(&map_item, (int *)&out->source_fingerprint);
        CHECK_CBOR_ERROR(err, result, exit);
        ADVANCE(&map_item, result, exit);
    }

    if (is_map_key(&map_item, 3)) {
        ADVANCE(&map_item, result, exit);
        CHECK_IS_TYPE(&map_item, unsigned_integer, result, exit);
        int val;
        err = cbor_value_get_int(&map_item, &val);
        CHECK_CBOR_ERROR(err, result, exit);
        out->depth = val;
        ADVANCE(&map_item, result, exit);
    }

    if (out->components_count == 0 && out->source_fingerprint == 0) {
        result = URC_EUNHANDLEDCASE;
    }

    LEAVE_CONTAINER_SAFELY(iter, &map_item, result, exit);

exit:
    return result;
}

int urc_crypto_hdkey_index_component_parse(CborValue *iter, child_index_component *out);
int urc_crypto_hdkey_range_component_parse(CborValue *iter, child_range_component *out);
int urc_crypto_hdkey_pair_component_parse(CborValue *iter, child_pair_component *out);

int urc_crypto_hdkey_pathcomponent_parse(CborValue *iter, path_component *out)
{
    int result = URC_OK;
    out->type = path_component_type_na;

    CborError err;
    if (!cbor_value_is_array(iter)) {
        result = urc_crypto_hdkey_index_component_parse(iter, &out->component.index);
        if (result != URC_OK) {
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

    result = urc_crypto_hdkey_range_component_parse(iter, &out->component.range);
    if (result == URC_OK) {
        out->type = path_component_type_range;
        goto exit;
    }

    result = urc_crypto_hdkey_pair_component_parse(iter, &out->component.pair);
    if (result == URC_OK) {
        out->type = path_component_type_pair;
        goto exit;
    }

exit:
    return result;
}

int urc_crypto_hdkey_index_component_parse(CborValue *iter, child_index_component *out)
{
    int result = URC_OK;

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

int urc_crypto_hdkey_range_component_parse(CborValue *iter, child_range_component *out)
{
    int result = URC_OK;

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

int urc_crypto_hdkey_pair_component_parse(CborValue *iter, child_pair_component *out)
{
    int result = URC_OK;

    CHECK_IS_TYPE(iter, array, result, exit)

    CborValue item;
    CborError err = cbor_value_enter_container(iter, &item);
    CHECK_CBOR_ERROR(err, result, exit);

    result = urc_crypto_hdkey_index_component_parse(&item, &out->internal);
    if (result != URC_OK) {
        goto exit;
    }

    result = urc_crypto_hdkey_index_component_parse(&item, &out->external);
    if (result != URC_OK) {
        goto exit;
    }

    LEAVE_CONTAINER_SAFELY(iter, &item, result, exit);

exit:
    return result;
}

int urc_hdkey_getversion(const crypto_hdkey *hdkey, uint32_t *out)
{
    *out = 0;
    switch (hdkey->type) {
    case hdkey_type_master:
        *out = BIP32_VER_MAIN_PRIVATE;
        break;
    case hdkey_type_derived:
        switch (hdkey->key.derived.useinfo.network) {
        case CRYPTO_COININFO_MAINNET:
            *out = hdkey->key.derived.is_private ? BIP32_VER_MAIN_PRIVATE : BIP32_VER_MAIN_PUBLIC;
            break;
        case CRYPTO_COININFO_TESTNET:
            *out = hdkey->key.derived.is_private ? BIP32_VER_TEST_PRIVATE : BIP32_VER_TEST_PUBLIC;
            break;
        default:
            return URC_EUNHANDLEDCASE;
        }
        break;
    default:
        return URC_EUNHANDLEDCASE;
    }
    return URC_OK;
}

int urc_hdkey_getdepth(const crypto_hdkey *hdkey, uint8_t *out)
{
    *out = 0;
    switch (hdkey->type) {
    case hdkey_type_master:
        break;
    case hdkey_type_derived: {
        *out = hdkey->key.derived.origin.components_count;
        for (size_t idx = 0; idx < hdkey->key.derived.children.components_count; idx++) {
            if (hdkey->key.derived.children.components[idx].type == path_component_type_index) {
                *out += 1;
            }
        }
        break;
    }
    default:
        return URC_EUNHANDLEDCASE;
    }
    return URC_OK;
}

int urc_hdkey_getchildnumber(const crypto_hdkey *hdkey, uint32_t *out)
{
    *out = 0;
    switch (hdkey->type) {
    case hdkey_type_master:
        break;
    case hdkey_type_derived:
        if (hdkey->key.derived.origin.components_count == 0) {
            break;
        }
        const size_t last_origincomponent_idx = hdkey->key.derived.origin.components_count - 1;
        const path_component *last_origincomponent = &hdkey->key.derived.origin.components[last_origincomponent_idx];
        assert(last_origincomponent->type == path_component_type_index);
        const uint32_t hardened_flag = last_origincomponent->component.index.is_hardened ? 0x80000000 : 0;
        const uint32_t childnum = last_origincomponent->component.index.index | hardened_flag;
        if (hdkey->key.derived.children.components_count == 0) {
            *out = childnum;
            break;
        }

        const size_t last_derivedcomponent_idx = hdkey->key.derived.children.components_count - 1;
        __attribute__((unused)) const path_component *last_derivedcomponent =
            &hdkey->key.derived.children.components[last_derivedcomponent_idx];
        assert(last_derivedcomponent->type == path_component_type_wildcard);
        *out = 0xfffffffe;
        break;
    default:
        return URC_EUNHANDLEDCASE;
    }
    return URC_OK;
}

int urc_hdkey_getparentfingerprint(const crypto_hdkey *hdkey, uint32_t *out)
{
    *out = 0;
    switch (hdkey->type) {
    case hdkey_type_master:
        break;
    case hdkey_type_derived:
        *out = hdkey->key.derived.parent_fingerprint;
        break;
    default:
        return URC_EUNHANDLEDCASE;
    }
    return URC_OK;
}

int urc_hdkey_getchaincode(const crypto_hdkey *hdkey, uint8_t **out)
{
    switch (hdkey->type) {
    case hdkey_type_master:
        *out = (uint8_t *)hdkey->key.master.chaincode;
        break;
    case hdkey_type_derived:
        *out = (uint8_t *)hdkey->key.derived.chaincode;
        break;
    default:
        return URC_EUNHANDLEDCASE;
    }
    return URC_OK;
}

int urc_hdkey_getkeydata(const crypto_hdkey *hdkey, uint8_t **out)
{
    switch (hdkey->type) {
    case hdkey_type_master:
        *out = (uint8_t *)hdkey->key.master.keydata;
        break;
    case hdkey_type_derived:
        *out = (uint8_t *)hdkey->key.derived.keydata;
        break;
    default:
        return URC_EUNHANDLEDCASE;
    }
    return URC_OK;
}

int urc_hdkey_getkeyorigin_levels(const crypto_hdkey *hdkey, size_t *out)
{
    switch (hdkey->type) {
    case hdkey_type_master:
        *out = 0;
        return URC_OK;
    case hdkey_type_derived:
        *out = hdkey->key.derived.origin.components_count;
        return URC_OK;
    default:
        return URC_EUNHANDLEDCASE;
    }
}

int format_hdkey_path_component(const path_component *component, char *out, size_t out_len)
{
    switch (component->type) {
    case path_component_type_index:
        return snprintf(out, out_len, "/%d%s", component->component.index.index,
                        component->component.index.is_hardened ? "'" : "");
    case path_component_type_range: {
        const child_range_component *range = &component->component.range;
        int len = snprintf(out, out_len, "/<%d%s", range->low, range->is_hardened ? "'" : "");
        size_t total_len = len;
        if (len < 0 || (size_t)len >= out_len) {
            return len;
        }
        for (uint32_t i = range->low + 1; i <= range->high; i++) {
            len = snprintf(&out[total_len], out_len - total_len, ";%d%s", i, range->is_hardened ? "'" : "");
            total_len += len;
            if (len < 0)
                return len;
            if (total_len >= out_len)
                return (int)total_len;
        }
        len = snprintf(&out[total_len], out_len - total_len, ">");
        total_len += len;
        if (len < 0)
            return len;
        return (int)total_len;
    }
    case path_component_type_wildcard:
        return snprintf(out, out_len, "/*");
    case path_component_type_pair: {
        char *hardened = component->component.pair.external.is_hardened ? "'" : "";
        return snprintf(out, out_len, "/<%d%s,%d%s>", component->component.pair.external.index, hardened,
                        component->component.pair.internal.index, hardened);
    }
    default:
        return URC_EINVALIDARG;
    }
}

int format_keyorigin(const crypto_hdkey *hdkey, char *out, size_t out_len)
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
        return URC_EINVALIDARG;
    }

    const path_component *comps = NULL;
    size_t comps_count = 0;
    if (hdkey->type == hdkey_type_derived) {
        comps = hdkey->key.derived.origin.components;
        comps_count = hdkey->key.derived.origin.components_count;
    }

    int total_len = 0;
    int len = snprintf(out, out_len, "[%08x", fpr);
    CHECK_SNPRINTF_BOUNDS(out_len, total_len, len);

    for (size_t idx = 0; idx < comps_count; idx++) {
        len = format_hdkey_path_component(&comps[idx], &out[total_len], out_len - total_len);
        CHECK_SNPRINTF_BOUNDS(out_len, total_len, len);
    }
    len = snprintf(&out[total_len], out_len - total_len, "]");
    CHECK_SNPRINTF_BOUNDS(out_len, total_len, len);
    return total_len;
}

int format_keyderivationpath(const crypto_hdkey *hdkey, char *out, size_t out_len)
{
    if (hdkey->type == hdkey_type_na) {
        return -1;
    }
    if (hdkey->type == hdkey_type_master) {
        return 0;
    }
    if (out_len == 0) {
        return -1;
    }
    int total_len = 0;

    const path_component *comps = hdkey->key.derived.children.components;
    size_t comps_count = comps_count = hdkey->key.derived.children.components_count;
    for (size_t idx = 0; idx < comps_count; idx++) {
        int len = format_hdkey_path_component(&comps[idx], &out[total_len], out_len - total_len);
        CHECK_SNPRINTF_BOUNDS(out_len, total_len, len);
    }
    return total_len;
}

int urc_crypto_hdkey_format(const crypto_hdkey *hdkey, char **out)
{
    if (hdkey == NULL || hdkey->type == hdkey_type_na || out == NULL) {
        return URC_EINVALIDARG;
    }

    int result = URC_OK;

    uint32_t version;
    result = urc_hdkey_getversion(hdkey, &version);
    if (result != URC_OK) {
        return result;
    }
    uint8_t depth;
    result = urc_hdkey_getdepth(hdkey, &depth);
    if (result != URC_OK) {
        return result;
    }
    uint32_t child_num;
    result = urc_hdkey_getchildnumber(hdkey, &child_num);
    if (result != URC_OK) {
        return result;
    }
    uint32_t parent_fpr;
    result = urc_hdkey_getparentfingerprint(hdkey, &parent_fpr);
    if (result != URC_OK) {
        return result;
    }
    parent_fpr = htonl(parent_fpr);
    uint8_t *chaincode;
    result = urc_hdkey_getchaincode(hdkey, &chaincode);
    if (result != URC_OK) {
        return result;
    }
    uint8_t *keydata;
    result = urc_hdkey_getkeydata(hdkey, &keydata);
    if (result != URC_OK) {
        return result;
    }
    unsigned char *priv_key = NULL;
    size_t priv_key_len = 0;
    unsigned char *pub_key = NULL;
    size_t pub_key_len = 0;
    uint32_t serialization_flag = 0;
    if (hdkey->type == hdkey_type_master || hdkey->key.derived.is_private) {
        priv_key = keydata + 1;
        priv_key_len = CRYPTO_HDKEY_KEYDATA_SIZE - 1;
        serialization_flag = BIP32_FLAG_KEY_PRIVATE;
    } else {
        pub_key = keydata;
        pub_key_len = CRYPTO_HDKEY_KEYDATA_SIZE;
        serialization_flag = BIP32_FLAG_KEY_PUBLIC;
    }

    int urc_result = URC_OK;
    struct ext_key wally_key;
    int wally_result = bip32_key_init(version, depth, child_num, chaincode, CRYPTO_HDKEY_CHAINCODE_SIZE, pub_key, pub_key_len,
                                      priv_key, priv_key_len, NULL, 0, (uint8_t *)&parent_fpr, sizeof(uint32_t), &wally_key);
    CHECK_WALLY_ERROR(wally_result, urc_result, exit);

    wally_result = bip32_key_to_base58(&wally_key, serialization_flag, out);
    CHECK_WALLY_ERROR(wally_result, urc_result, exit);

exit:
    wally_bzero(&wally_key, sizeof(wally_key));
    return urc_result;
}
