
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "utils.h"

const int cbor_flags = CborValidateBasic | CborValidateMapKeysAreUnique | CborValidateMapIsSorted | CborValidateUtf8 |
                       CborValidateNoUndefined | CborValidateCompleteData;

int check_map_key(CborValue *cursor, int expected)
{
    int key;
    if (!cbor_value_is_unsigned_integer(cursor)) {
        return URC_EUNEXPECTEDTYPE;
    }
    CborError err = cbor_value_get_int_checked(cursor, &key);
    if (err != CborNoError) {
        return URC_ECBORINTERNALERROR;
    }
    if (key != expected) {
        return URC_EUNEXPECTEDMAPKEY;
    }
    return URC_OK;
}

bool is_map_key(CborValue *cursor, int expected)
{
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

int check_tag(CborValue *cursor, unsigned long expected_tag)
{
    if (!cbor_value_is_tag(cursor)) {
        return URC_EUNEXPECTEDTYPE;
    }
    CborTag tag;
    CborError err = cbor_value_get_tag(cursor, &tag);
    if (err != CborNoError) {
        return URC_ECBORINTERNALERROR;
    }
    if (tag != expected_tag) {
        return URC_EUNEXPECTEDTAG;
    }
    return URC_OK;
}

bool is_tag(CborValue *cursor, unsigned long expected_tag)
{
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

int copy_fixed_size_byte_string(CborValue *cursor, uint8_t *buffer, size_t len)
{
    if (!cbor_value_is_byte_string(cursor)) {
        return URC_EUNEXPECTEDTYPE;
    }
    size_t cborlen;
    CborError err = cbor_value_get_string_length(cursor, &cborlen);
    if (err != CborNoError) {
        return URC_ECBORINTERNALERROR;
    }
    if (cborlen != len) {
        return URC_EUNEXPECTEDSTRINGLENGTH;
    }
    err = cbor_value_copy_byte_string(cursor, buffer, &len, NULL);
    if (err != CborNoError) {
        return URC_ECBORINTERNALERROR;
    }
    return URC_OK;
}
