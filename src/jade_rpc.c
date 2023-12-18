
#include <stdio.h>

#include "cborjson.h"
#include "wally_core.h"

#include "urc/jade_rpc.h"

#include "macros.h"
#include "utils.h"

int urc_jade_rpc_parse(const uint8_t *cbor, size_t cbor_len, char **out) {
    CborParser parser;
    CborValue value;
    CborError err = cbor_parser_init(cbor, cbor_len, 0, &parser, &value);
    if (err != CborNoError) {
        return URC_ECBORINTERNALERROR;
    }
    FILE *stream = NULL;
    *out = NULL;
    size_t buffer_len = cbor_len;
    do {
        wally_free(*out);
        *out = wally_malloc(buffer_len);
        if (*out == NULL) {
            return URC_EWALLYINTERNALERROR;
        }
        stream = fmemopen(*out, buffer_len, "w");
        if (stream == NULL) {
            wally_free(*out);
            *out = NULL;
            return URC_EINTERNALERROR;
        }
        setbuf(stream, NULL);
        err = cbor_value_to_json(stream, &value, CborConvertIgnoreTags | CborConvertRequireMapStringKeys);
        buffer_len *= 2;
    } while (err == CborErrorIO);
    fclose(stream);
    if (err != CborNoError) {
        wally_free(*out);
        *out = NULL;
        return URC_ECBORINTERNALERROR;
    }
    return URC_OK;
}