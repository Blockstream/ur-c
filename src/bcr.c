
#include "tinycbor/cbor.h"

#include "bcr/bcr.h"

#include "internals.h"

int cbor_flags = CborValidateBasic | CborValidateMapKeysAreUnique | CborValidateMapIsSorted | CborValidateUtf8 | CborValidateNoUndefined | CborValidateCompleteData;


bcr_error parse_seed(const uint8_t *buffer, unsigned int size, crypto_seed* out) {
    CborParser parser;
    CborValue iter;
    CborError err;
    err = cbor_parser_init(buffer, size, cbor_flags, &parser, &iter);
    if (err != CborNoError) {
        bcr_error result = {.tag = bcr_error_tag_cborinternalerror, .internal.cbor = err };
        return result;
    }
    return internal_parse_seed(&iter, out);
}

bcr_error parse_psbt(const uint8_t *buffer, unsigned int size, crypto_psbt* out) {
    CborParser parser;
    CborValue iter;
    CborError err;
    err = cbor_parser_init(buffer, size, cbor_flags, &parser, &iter);
    if (err != CborNoError) {
        bcr_error result = {.tag = bcr_error_tag_cborinternalerror, .internal.cbor = err };
        return result;
    }
    return internal_parse_psbt(&iter, out);
}

bcr_error parse_eckey(const uint8_t *buffer, unsigned int size, crypto_eckey* out) {
    CborParser parser;
    CborValue iter;
    CborError err;
    err = cbor_parser_init(buffer, size, cbor_flags, &parser, &iter);
    if (err != CborNoError) {
        bcr_error result = {.tag = bcr_error_tag_cborinternalerror, .internal.cbor = err };
        return result;
    }
    return internal_parse_eckey(&iter, out);
}

bcr_error parse_p2pkh(const uint8_t *buffer, unsigned int size, crypto_p2pkh* out) {
    CborParser parser;
    CborValue iter;
    CborError err;
    err = cbor_parser_init(buffer, size, cbor_flags, &parser, &iter);
    if (err != CborNoError) {
        bcr_error result = {.tag = bcr_error_tag_cborinternalerror, .internal.cbor = err };
        return result;
    }
    return internal_parse_p2pkh(&iter, out);
}



