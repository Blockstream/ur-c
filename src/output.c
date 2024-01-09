
#include "wally_core.h"

#include "urc/crypto_output.h"
#include "urc/tags.h"

#include "internals.h"
#include "macros.h"
#include "utils.h"

int urc_crypto_output_keyexp_deserialize(CborValue *iter, output_keyexp *out);

int urc_crypto_output_deserialize(const uint8_t *buffer, size_t len, crypto_output *out)
{
    CborParser parser;
    CborValue iter;
    CborError err;
    err = cbor_parser_init(buffer, len, cbor_flags, &parser, &iter);
    if (err != CborNoError) {
        return URC_ECBORINTERNALERROR;
    }
    return urc_crypto_output_deserialize_impl(&iter, out);
}

int urc_crypto_output_deserialize_impl(CborValue *iter, crypto_output *out)
{
    int result = URC_OK;
    out->type = output_type_na;

    CHECK_IS_TYPE(iter, tag, result, exit);
    CborTag tag;
    CborError err = cbor_value_get_tag(iter, &tag);
    CHECK_CBOR_ERROR(err, result, exit);

    switch (tag) {
    case urc_urtypes_tags_output_sh:
        ADVANCE(iter, result, exit);
        int output_type = output_type_sh;
        if (is_tag(iter, urc_urtypes_tags_output_wsh)) {
            ADVANCE(iter, result, exit);
            output_type = output_type_sh_wsh;
        }
        result = urc_crypto_output_keyexp_deserialize(iter, &out->output.key);
        if (result != URC_OK) {
            goto exit;
        }
        out->type = output_type;
        break;
    case urc_urtypes_tags_output_wsh:
        ADVANCE(iter, result, exit);
        result = urc_crypto_output_keyexp_deserialize(iter, &out->output.key);
        if (result != URC_OK) {
            goto exit;
        }
        out->type = output_type_wsh;
        break;
    case urc_urtypes_tags_output_rawscript:
        ADVANCE(iter, result, exit);
        result = copy_fixed_size_byte_string(iter, (uint8_t *)out->output.raw, URC_RAWSCRIPT_LEN);
        if (result != URC_OK) {
            goto exit;
        }
        out->type = output_type_rawscript;
        break;
    case urc_urtypes_tags_output_taproot:
        result = URC_ETAPROOTNOTSUPPORTED;
        goto exit;

        break;
    default:
        result = urc_crypto_output_keyexp_deserialize(iter, &out->output.key);
        if (result != URC_OK) {
            goto exit;
        }
        out->type = output_type__;
    }

exit:
    return result;
}

int urc_crypto_output_keyexp_deserialize(CborValue *iter, output_keyexp *out)
{
    int result = URC_OK;
    out->keytype = keyexp_keytype_na;

    CHECK_IS_TYPE(iter, tag, result, exit);
    CborTag tag;
    CborError err = cbor_value_get_tag(iter, &tag);
    CHECK_CBOR_ERROR(err, result, exit);
    ADVANCE(iter, result, exit);

    switch (tag) {
    case urc_urtypes_tags_output_pk:
        out->type = keyexp_type_pk;
        break;
    case urc_urtypes_tags_output_pkh:
        out->type = keyexp_type_pkh;
        break;
    case urc_urtypes_tags_output_wpkh:
        out->type = keyexp_type_wpkh;
        break;
    case urc_urtypes_tags_output_cosigner:
        out->type = keyexp_type_cosigner;
        break;
    default:
        result = URC_EUNHANDLEDCASE;
        goto exit;
    }

    err = cbor_value_get_tag(iter, &tag);
    CHECK_CBOR_ERROR(err, result, exit);
    ADVANCE(iter, result, exit);

    switch (tag) {
    case urc_urtypes_tags_crypto_eckey:
        result = urc_crypto_eckey_deserialize_impl(iter, &out->key.eckey);
        if (result != URC_OK) {
            goto exit;
        }
        out->keytype = keyexp_keytype_eckey;
        break;
    case urc_urtypes_tags_crypto_hdkey:
        result = urc_crypto_hdkey_deserialize_impl(iter, &out->key.hdkey);
        if (result != URC_OK) {
            goto exit;
        }
        out->keytype = keyexp_keytype_hdkey;

        break;
    default:
        result = URC_EUNEXPECTEDTAG;
    }

exit:
    return result;
}

typedef int (*hdkey_formatter)(const crypto_hdkey *, char *out, size_t out_len);
static int format_with_retry(const crypto_hdkey *key, hdkey_formatter formatter, char **out)
{
    int result = URC_OK;
    size_t out_len = 32;
    int len = 0;
    *out = NULL;
    do {
        out_len *= 2;
        wally_free(*out);
        *out = wally_malloc(out_len);
        if (!*out) {
            return URC_ENOMEM;
        }
        *out[0] = '\0';

        len = formatter(key, *out, out_len);
        if (len < 0) {
            result = URC_EINTERNALERROR;
            break;
        }
    } while ((size_t)len >= out_len);

    if (result != URC_OK) {
        wally_free(*out);
        *out = NULL;
    }
    return result;
}

int urc_crypto_hdkey_descriptor_format_impl(const crypto_hdkey *key, urc_crypto_output_format_mode mode, char **out)
{
    char *keyorigin = NULL;
    char *derivation_path = NULL;
    char *bip32_base58_key = NULL;

    int result = format_with_retry(key, format_keyorigin, &keyorigin);
    if (result != URC_OK) {
        goto exit;
    }
    size_t keyorigin_len = strlen(keyorigin);

    result = urc_crypto_hdkey_format(key, &bip32_base58_key);
    if (result != URC_OK) {
        goto exit;
    }
    size_t bip32_base58_key_len = strlen(bip32_base58_key);

    result = format_with_retry(key, format_keyderivationpath, &derivation_path);
    if (result != URC_OK) {
        goto exit;
    }
    size_t derivation_path_len = strlen(derivation_path);
    size_t keyorigin_levels;
    result = urc_hdkey_getkeyorigin_levels(key, &keyorigin_levels);
    if (result != URC_OK) {
        goto exit;
    }

    if (keyorigin_levels == 3 && derivation_path_len == 0 && mode == urc_crypto_output_format_mode_BIP44_compatible) {
        wally_free(derivation_path);
        derivation_path = wally_malloc(5);
        if (!derivation_path) {
            result = URC_ENOMEM;
            goto exit;
        }
        snprintf(derivation_path, 5, "/0/*");
        derivation_path_len = strlen(derivation_path);
    }

    size_t out_len = keyorigin_len + bip32_base58_key_len + derivation_path_len + 1;
    *out = wally_malloc(out_len);
    if (!*out) {
        result = URC_ENOMEM;
        goto exit;
    }

    int len = snprintf(*out, out_len, "%s%s%s", keyorigin, bip32_base58_key, derivation_path);
    if (len < 0) {
        wally_free(*out);
        result = URC_EINTERNALERROR;
    }

exit:
    wally_free(derivation_path);
    wally_free(bip32_base58_key);
    wally_free(keyorigin);
    return result;
}

int urc_crypto_output_format(const crypto_output *output, urc_crypto_output_format_mode mode, char **out)
{
    if (!output || !out || output->type == output_type_na) {
        return URC_EINVALIDARG;
    }

    char *outer_desc;
    char *outer_desc_end;
    switch (output->type) {
    case output_type__:
        outer_desc = "";
        outer_desc_end = "";
        break;
    case output_type_sh:
        outer_desc = "sh(";
        outer_desc_end = ")";
        break;
    case output_type_wsh:
        outer_desc = "wsh(";
        outer_desc_end = ")";
        break;
    case output_type_sh_wsh:
        outer_desc = "sh(wsh(";
        outer_desc_end = "))";
        break;
    case output_type_rawscript:
        outer_desc = "raw(";
        outer_desc_end = ")";
        break;
    default:
        return URC_EINVALIDARG;
    }

    char *inner_desc;
    char *inner_desc_end;
    switch (output->output.key.type) {
    case keyexp_type_pk:
        inner_desc = "pk(";
        inner_desc_end = ")";
        break;
    case keyexp_type_pkh:
        inner_desc = "pkh(";
        inner_desc_end = ")";
        break;
    case keyexp_type_wpkh:
        inner_desc = "wpkh(";
        inner_desc_end = ")";
        break;
    case keyexp_type_cosigner:
        inner_desc = "cosigner(";
        inner_desc_end = ")";
        break;
    default:
        return URC_EINVALIDARG;
    }
    int key_format_result = URC_OK;
    char *key = NULL; // key as in KEY in bitcoin descriptor doc
    switch (output->output.key.keytype) {
    case keyexp_keytype_eckey:
        key_format_result = urc_crypto_eckey_format(&output->output.key.key.eckey, &key);
        break;
    case keyexp_keytype_hdkey:
        key_format_result = urc_crypto_hdkey_descriptor_format_impl(&output->output.key.key.hdkey, mode, &key);
        break;
    default:
        return URC_EINVALIDARG;
    }
    if (key_format_result != URC_OK) {
        return key_format_result;
    }
    size_t descriptor_len =
        strlen(outer_desc) + strlen(inner_desc) + strlen(key) + strlen(inner_desc_end) + strlen(outer_desc_end) + 1;
    *out = wally_malloc(descriptor_len);
    if (!*out) {
        wally_free(key);
        return URC_ENOMEM;
    }
    int len = snprintf(*out, descriptor_len, "%s%s%s%s%s", outer_desc, inner_desc, key, inner_desc_end, outer_desc_end);
    wally_free(key);
    if (len < 0) {
        wally_free(*out);
        *out = NULL;
        return URC_EINTERNALERROR;
    }
    return URC_OK;
}
