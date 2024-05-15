
#ifdef WIN32
#include <winsock2.h>
#else
#include <arpa/inet.h>
#endif

#include "wally_bip32.h"

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

uint32_t urc_hdkey_getversion(const crypto_hdkey *hdkey)
{
    switch (hdkey->type) {
    case hdkey_type_master:
        return 0x0488ADE4;
    case hdkey_type_derived:
        switch (hdkey->key.derived.useinfo.network) {
        case CRYPTO_COININFO_MAINNET:
            return hdkey->key.derived.is_private ? 0x0488ADE4 : 0x0488B21E;
        case CRYPTO_COININFO_TESTNET:
            return hdkey->key.derived.is_private ? 0x04358394 : 0x043587CF;
        default:
            return 0;
        }
    default:
        assert(false);
    }
    assert(false);
    return 0;
}

uint8_t urc_hdkey_getdepth(const crypto_hdkey *hdkey)
{
    switch (hdkey->type) {
    case hdkey_type_master:
        return 0x00;
    case hdkey_type_derived: {
        uint8_t depth = hdkey->key.derived.origin.components_count;
        for (size_t idx = 0; idx < hdkey->key.derived.children.components_count; idx++) {
            if (hdkey->key.derived.children.components[idx].type == path_component_type_index) {
                depth += 1;
            }
        }
        return depth;
    }
    default:
        assert(false);
    }
    assert(false);
    return 0;
}

uint32_t urc_hdkey_getchildnumber(const crypto_hdkey *hdkey)
{
    switch (hdkey->type) {
    case hdkey_type_master:
        return 0;
    case hdkey_type_derived:
        if (hdkey->key.derived.origin.components_count == 0) {
            return 0;
        }
        const size_t last_origincomponent_idx = hdkey->key.derived.origin.components_count - 1;
        const path_component *last_origincomponent = &hdkey->key.derived.origin.components[last_origincomponent_idx];
        assert(last_origincomponent->type == path_component_type_index);
        uint32_t hardened_multiplier = 0x80000000 * last_origincomponent->component.index.is_hardened;
        uint32_t childnum = last_origincomponent->component.index.index + hardened_multiplier;
        if (hdkey->key.derived.children.components_count == 0) {
            return childnum;
        }

        const size_t last_derivedcomponent_idx = hdkey->key.derived.children.components_count - 1;
        __attribute__((unused)) const path_component *last_derivedcomponent =
            &hdkey->key.derived.children.components[last_derivedcomponent_idx];
        assert(last_derivedcomponent->type == path_component_type_wildcard);
        return 0xfffffffe;
    default:
        assert(false);
    }
    assert(false);
    return 0;
}

uint32_t urc_hdkey_getparentfingerprint(const crypto_hdkey *hdkey)
{
    switch (hdkey->type) {
    case hdkey_type_master:
        return 0;
    case hdkey_type_derived:
        return hdkey->key.derived.parent_fingerprint;
    default:
        assert(false);
    }
    assert(false);
    return 0;
}

uint8_t *urc_hdkey_getchaincode(const crypto_hdkey *hdkey)
{
    switch (hdkey->type) {
    case hdkey_type_master:
        return (uint8_t *)hdkey->key.master.chaincode;
    case hdkey_type_derived:
        return (uint8_t *)hdkey->key.derived.chaincode;
    default:
        assert(false);
    }
    assert(false);
    return 0;
}

uint8_t *urc_hdkey_getkeydata(const crypto_hdkey *hdkey)
{
    switch (hdkey->type) {
    case hdkey_type_master:
        return (uint8_t *)hdkey->key.master.keydata;
    case hdkey_type_derived:
        return (uint8_t *)hdkey->key.derived.keydata;
    default:
        assert(false);
    }
    assert(false);
    return NULL;
}

bool bip32_serialize(const crypto_hdkey *hdkey, uint8_t out[BIP32_SERIALIZED_LEN])
{
    if (hdkey->type == hdkey_type_na) {
        return false;
    }
    size_t cursor = 0;

    uint32_t *version = (uint32_t *)&out[cursor]; // 0 - 3
    cursor += sizeof(uint32_t);
    *version = htonl(urc_hdkey_getversion(hdkey));
    if (*version == 0) {
        return false;
    }

    uint8_t *depth = &out[cursor]; // 4
    cursor += sizeof(uint8_t);
    *depth = urc_hdkey_getdepth(hdkey);

    uint32_t *parent_fingerprint = (uint32_t *)&out[cursor]; // 5 - 8
    cursor += sizeof(uint32_t);
    *parent_fingerprint = htonl(urc_hdkey_getparentfingerprint(hdkey));

    uint32_t *child_number = (uint32_t *)&out[cursor]; // 9 - 12
    cursor += sizeof(uint32_t);
    *child_number = htonl(urc_hdkey_getchildnumber(hdkey));

    uint8_t(*chain_code)[CRYPTO_HDKEY_CHAINCODE_SIZE] = (uint8_t(*)[CRYPTO_HDKEY_CHAINCODE_SIZE]) & out[cursor]; // 13 - 44
    cursor += CRYPTO_HDKEY_CHAINCODE_SIZE;
    const uint8_t *hd_chaincode = urc_hdkey_getchaincode(hdkey);
    memcpy(chain_code, hd_chaincode, CRYPTO_HDKEY_CHAINCODE_SIZE);

    uint8_t(*key_data)[CRYPTO_HDKEY_KEYDATA_SIZE] = (uint8_t(*)[CRYPTO_HDKEY_KEYDATA_SIZE]) & out[cursor]; // 45 - 77
    cursor += CRYPTO_HDKEY_KEYDATA_SIZE;
    const uint8_t *hd_keydata = urc_hdkey_getkeydata(hdkey);
    memcpy(key_data, hd_keydata, CRYPTO_HDKEY_KEYDATA_SIZE);

    return true;
}

int format_keyorigin(const crypto_hdkey *hdkey, char *out, size_t out_len)
{
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
        int len = snprintf(out, out_len, "[%08x", fpr);
        total_len += len;
        // either an error or an out-of-space
        if (len < 0 || (size_t)total_len >= out_len) {
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
                len = snprintf(&out[total_len], out_len - total_len, "/%d%s", comp->component.index.index,
                               comp->component.index.is_hardened ? "'" : "");
                break;
            default:
                return -1;
            }
            total_len += len;
            // either an error or an out-of-space
            if (len < 0 || (size_t)total_len >= out_len) {
                return len < 0 ? len : total_len;
            }
        }
    }
    int len = snprintf(&out[total_len], out_len - total_len, "]");
    if (len < 0) {
        return len;
    }
    total_len += len;
    return total_len;
}

int format_keyderivationpath(const crypto_hdkey *hdkey, char *out, size_t out_len)
{
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
                len = snprintf(&out[total_len], out_len - total_len, "/%d'", comp->component.index.index);
            } else {
                len = snprintf(&out[total_len], out_len - total_len, "/%d", comp->component.index.index);
            }
            break;
        case path_component_type_wildcard:
            len = snprintf(&out[total_len], out_len - total_len, "/*");
            break;
        default:
            return -1;
        }
        total_len += len;
        if (len < 0 || (size_t)total_len >= out_len) {
            return len < 0 ? len : total_len;
        }
    }

    return total_len;
}

int urc_bip32_tobase58(const crypto_hdkey *hdkey, char **out)
{
    if (hdkey == NULL || hdkey->type == hdkey_type_na || out == NULL) {
        return URC_EINVALIDARG;
    }

    const uint32_t version = urc_hdkey_getversion(hdkey);
    const uint8_t depth = urc_hdkey_getdepth(hdkey);
    const uint32_t child_num = urc_hdkey_getchildnumber(hdkey);
    const uint32_t parent_fpr = htonl(urc_hdkey_getparentfingerprint(hdkey));
    const uint8_t *chaincode = urc_hdkey_getchaincode(hdkey);
    uint8_t *keydata = urc_hdkey_getkeydata(hdkey);
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
