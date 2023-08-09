
#include <stdint.h>
#include <stdio.h>

#include "macros.h"
#include "utils.h"

bcr_error check_map_key(CborValue *cursor, int expected) {
    bcr_error result = {.tag = bcr_error_tag_noerror};
    int key;
    if (!cbor_value_is_unsigned_integer(cursor)) {
        result.tag = bcr_error_tag_wrongtype;
        return result;
    }
    CborError err = cbor_value_get_int_checked(cursor, &key);
    if (err != CborNoError) {
        result.tag = bcr_error_tag_cborinternalerror;
        result.internal.cbor = err;
        return result;
    }
    if (key != expected) {
        result.tag = bcr_error_tag_wrongmapkey;
    }
    return result;
}

bool is_map_key(CborValue *cursor, int expected) {
    if (!cbor_value_is_unsigned_integer(cursor)) {
        return false;
    }
    int key;
    CborError err = cbor_value_get_int_checked(cursor, &key);
    if (err != CborNoError) {
        return false;
    }
    if (key != expected) {
        return false;
    }
    return true;
}

bcr_error check_tag(CborValue *cursor, int expected_tag) {
    bcr_error result = {.tag = bcr_error_tag_noerror};
    if (!cbor_value_is_tag(cursor)) {
        result.tag = bcr_error_tag_wrongtype;
        return result;
    }
    CborTag tag;
    CborError err = cbor_value_get_tag(cursor, &tag);
    if (err != CborNoError) {
        result.tag = bcr_error_tag_cborinternalerror;
        result.internal.cbor = err;
        return result;
    }
    if (tag != expected_tag) {
        result.tag = bcr_error_tag_wrongtag;
        return result;
    }
    return result;
}

bcr_error copy_fixed_size_byte_string(CborValue *cursor, uint8_t *buffer, size_t expected) {
    bcr_error result = {.tag = bcr_error_tag_noerror};
    if (!cbor_value_is_byte_string(cursor)) {
        result.tag = bcr_error_tag_wrongtype;
        return result;
    }
    size_t len;
    CborError err = cbor_value_get_string_length(cursor, &len);
    if (err != CborNoError) {
        result.tag = bcr_error_tag_cborinternalerror;
        result.internal.cbor = err;
        return result;
    }
    if (len != expected) {
        result.tag = bcr_error_tag_wrongstringlength;
        return result;
    }
    size_t buflen = expected;
    cbor_value_copy_byte_string(cursor, buffer, &buflen, NULL);
    return result;
}
