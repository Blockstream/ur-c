
#include "tinycbor/cbor.h"

#include "ur-c/crypto_output.h"
#include "ur-c/error.h"
#include "ur-c/tags.h"

#include "internals.h"
#include "macros.h"
#include "utils.h"

urc_error internal_parse_keyexp(CborValue *iter, output_keyexp *out);

urc_error parse_output(size_t size, const uint8_t buffer[size], crypto_output *out) {
    CborParser parser;
    CborValue iter;
    CborError err;
    err = cbor_parser_init(buffer, size, cbor_flags, &parser, &iter);
    if (err != CborNoError) {
        urc_error result = {.tag = urc_error_tag_cborinternalerror, .internal.cbor = err};
        return result;
    }
    return internal_parse_output(&iter, out);
}

urc_error internal_parse_output(CborValue *iter, crypto_output *out) {
    urc_error result = {.tag = urc_error_tag_noerror};
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
        result = internal_parse_keyexp(iter, &out->output.key);
        if (result.tag != urc_error_tag_noerror) {
            goto exit;
        }
        out->type = output_type;
        break;
    case urc_urtypes_tags_output_wsh:
        ADVANCE(iter, result, exit);
        result = internal_parse_keyexp(iter, &out->output.key);
        if (result.tag != urc_error_tag_noerror) {
            goto exit;
        }
        out->type = output_type_wsh;
        break;
    case urc_urtypes_tags_output_rawscript:
        ADVANCE(iter, result, exit);
        result = copy_fixed_size_byte_string(iter, 32, (uint8_t *)out->output.raw);
        if (result.tag != urc_error_tag_noerror) {
            goto exit;
        }
        out->type = output_type_rawscript;
        break;
    case urc_urtypes_tags_output_taproot:
        result.tag = urc_error_tag_taprootnotsupported;
        goto exit;

        break;
    default:
        result = internal_parse_keyexp(iter, &out->output.key);
        if (result.tag != urc_error_tag_noerror) {
            goto exit;
        }
        out->type = output_type__;
    }

exit:
    return result;
}

urc_error internal_parse_keyexp(CborValue *iter, output_keyexp *out) {
    urc_error result = {.tag = urc_error_tag_noerror};
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
        result.tag = urc_error_tag_unhandledcase;
        goto exit;
    }

    err = cbor_value_get_tag(iter, &tag);
    CHECK_CBOR_ERROR(err, result, exit);
    ADVANCE(iter, result, exit);

    switch (tag) {
    case urc_urtypes_tags_crypto_eckey:
        result = internal_parse_eckey(iter, &out->key.eckey);
        if (result.tag != urc_error_tag_noerror) {
            goto exit;
        }
        out->keytype = keyexp_keytype_eckey;
        break;
    case urc_urtypes_tags_crypto_hdkey:
        result = internal_parse_hdkey(iter, &out->key.hdkey);
        if (result.tag != urc_error_tag_noerror) {
            goto exit;
        }
        out->keytype = keyexp_keytype_hdkey;

        break;
    default:
        result.tag = urc_error_tag_wrongtag;
    }

exit:
    return result;
}
