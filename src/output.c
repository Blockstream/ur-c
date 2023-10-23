
#include "cbor.h"

#include "urc/crypto_output.h"
#include "urc/error.h"
#include "urc/tags.h"

#include "internals.h"
#include "macros.h"
#include "utils.h"

int urc_crypto_outpute_keyexp_parse(CborValue *iter, output_keyexp *out);

int urc_crypto_output_parse(const uint8_t *buffer, size_t len, crypto_output *out) {
    CborParser parser;
    CborValue iter;
    CborError err;
    err = cbor_parser_init(buffer, len, cbor_flags, &parser, &iter);
    if (err != CborNoError) {
        return  URC_ECBORINTERNALERROR;
    }
    return urc_crypto_output_parse_impl(&iter, out);
}

int urc_crypto_output_parse_impl(CborValue *iter, crypto_output *out) {
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
        result = urc_crypto_outpute_keyexp_parse(iter, &out->output.key);
        if (result != URC_OK) {
            goto exit;
        }
        out->type = output_type;
        break;
    case urc_urtypes_tags_output_wsh:
        ADVANCE(iter, result, exit);
        result = urc_crypto_outpute_keyexp_parse(iter, &out->output.key);
        if (result != URC_OK) {
            goto exit;
        }
        out->type = output_type_wsh;
        break;
    case urc_urtypes_tags_output_rawscript:
        ADVANCE(iter, result, exit);
        result = copy_fixed_size_byte_string(iter, (uint8_t *)out->output.raw, 32);
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
        result = urc_crypto_outpute_keyexp_parse(iter, &out->output.key);
        if (result != URC_OK) {
            goto exit;
        }
        out->type = output_type__;
    }

exit:
    return result;
}

int urc_crypto_outpute_keyexp_parse(CborValue *iter, output_keyexp *out) {
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
        result = urc_crypto_eckey_parse_impl(iter, &out->key.eckey);
        if (result != URC_OK) {
            goto exit;
        }
        out->keytype = keyexp_keytype_eckey;
        break;
    case urc_urtypes_tags_crypto_hdkey:
        result = urc_crypto_hdkey_parse_impl(iter, &out->key.hdkey);
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
