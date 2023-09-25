
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "macros.h"
#include "utils.h"

const int cbor_flags = CborValidateBasic | CborValidateMapKeysAreUnique | CborValidateMapIsSorted | CborValidateUtf8 |
                 CborValidateNoUndefined | CborValidateCompleteData;

urc_error check_map_key(CborValue *cursor, int expected) {
    urc_error result = {.tag = urc_error_tag_noerror};
    int key;
    if (!cbor_value_is_unsigned_integer(cursor)) {
        result.tag = urc_error_tag_wrongtype;
        return result;
    }
    CborError err = cbor_value_get_int_checked(cursor, &key);
    if (err != CborNoError) {
        result.tag = urc_error_tag_cborinternalerror;
        result.internal.cbor = err;
        return result;
    }
    if (key != expected) {
        result.tag = urc_error_tag_wrongmapkey;
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

urc_error check_tag(CborValue *cursor, unsigned long expected_tag) {
    urc_error result = {.tag = urc_error_tag_noerror};
    if (!cbor_value_is_tag(cursor)) {
        result.tag = urc_error_tag_wrongtype;
        return result;
    }
    CborTag tag;
    CborError err = cbor_value_get_tag(cursor, &tag);
    if (err != CborNoError) {
        result.tag = urc_error_tag_cborinternalerror;
        result.internal.cbor = err;
        return result;
    }
    if (tag != expected_tag) {
        result.tag = urc_error_tag_wrongtag;
        return result;
    }
    return result;
}

bool is_tag(CborValue *cursor, unsigned long expected_tag) {
    if (!cbor_value_is_tag(cursor)) {
        return false;
    }
    CborTag tag;
    CborError err = cbor_value_get_tag(cursor, &tag);
    if (err != CborNoError) {
        return false;
    }
    if (tag != expected_tag) {
        return false;
    }
    return true;
}

urc_error copy_fixed_size_byte_string(CborValue *cursor, uint8_t *buffer, size_t len) {
    urc_error result = {.tag = urc_error_tag_noerror};
    if (!cbor_value_is_byte_string(cursor)) {
        result.tag = urc_error_tag_wrongtype;
        return result;
    }
    size_t cborlen;
    CborError err = cbor_value_get_string_length(cursor, &cborlen);
    if (err != CborNoError) {
        result.tag = urc_error_tag_cborinternalerror;
        result.internal.cbor = err;
        return result;
    }
    if (cborlen != len) {
        result.tag = urc_error_tag_wrongstringlength;
        return result;
    }
    err = cbor_value_copy_byte_string(cursor, buffer, &len, NULL);
    if (err != CborNoError) {
        result.tag = urc_error_tag_cborinternalerror;
        result.internal.cbor = err;
    }
    return result;
}

int copy_fixed_size_byte_string2(CborValue *cursor, uint8_t *buffer, size_t len) {
    int result = URC_OK;
    if (!cbor_value_is_byte_string(cursor)) {
        result = URC_EUNEXPECTEDTYPE;
        return result;
    }
    size_t cborlen;
    CborError err = cbor_value_get_string_length(cursor, &cborlen);
    if (err != CborNoError) {
        result = URC_ECBORINTERNALERROR;
        return result;
    }
    if (cborlen != len) {
        result = URC_EUNEXPECTEDSTRINGLENGTH;
        return result;
    }
    err = cbor_value_copy_byte_string(cursor, buffer, &len, NULL);
    if (err != CborNoError) {
        result = URC_ECBORINTERNALERROR;
    }
    return result;
}
