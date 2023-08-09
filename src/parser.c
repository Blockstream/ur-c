
#include <stdint.h>
#include <stdio.h>

#include "bcr/bcr.h"
#include "macros.h"
#include "parser.h"
#include "tinycbor/cbor.h"

static bcr_error check_map_key(CborValue *cursor, int expected) {
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

static bcr_error check_tag(CborValue *cursor, int expected_tag) {
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

static bcr_error copy_byte_string(CborValue *cursor, uint8_t *buffer, size_t expected) {
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

bcr_error internal_parse_seed(CborValue *iter, crypto_seed *out) {
    bcr_error result = {.tag = bcr_error_tag_noerror};

    if (!cbor_value_is_map(iter)) {
        result.tag = bcr_error_tag_wrongtype;
        goto exit;
    }

    CborValue item;
    CborError err;
    err = cbor_value_enter_container(iter, &item);
    CHECK_CBOR_ERROR(err, result, exit);

    result = check_map_key(&item, 1);
    if (result.tag != bcr_error_tag_noerror) {
        goto leave_and_exit;
    }

    ADVANCE(item, result, leave_and_exit);

    result = copy_byte_string(&item, out->seed, CRYPTO_SEED_SIZE);
    if (result.tag != bcr_error_tag_noerror) {
        goto leave_and_exit;
    }

    if (cbor_value_at_end(&item)) {
        goto leave_and_exit;
    }

    ADVANCE(item, result, leave_and_exit);

    result = check_map_key(&item, 2);
    if (result.tag != bcr_error_tag_noerror) {
        goto leave_and_exit;
    }

    ADVANCE(item, result, leave_and_exit);

    result = check_tag(&item, 100); // TODO: check whether this is an official RFC 8949 tag or what
    if (result.tag != bcr_error_tag_noerror) {
        goto leave_and_exit;
    }

    err = cbor_value_skip_tag(&item);
    CHECK_CBOR_ERROR(err, result, leave_and_exit)

    err = cbor_value_get_uint64(&item, &out->creation_date);
    CHECK_CBOR_ERROR(err, result, leave_and_exit)

leave_and_exit:
    while (!cbor_value_at_end(&item)) {
        cbor_value_advance(&item);
    }
    err = cbor_value_leave_container(iter, &item);
    assert(err == CborNoError);
exit:
    return result;
}


bcr_error internal_parse_psbt(CborValue *iter, crypto_psbt* out) {
    out->psbt_len = 0;
    bcr_error result = {.tag = bcr_error_tag_noerror};
    if(!cbor_value_is_byte_string(iter)) {
        result.tag = bcr_error_tag_wrongtype;
        return result;
    }
    size_t len;
    CborError err = cbor_value_get_string_length(iter, &len);
    CHECK_CBOR_ERROR(err, result, exit);

    if(out->buffer_size < len) {
        result.tag = bcr_error_tag_wrongstringlength;
        return result;
    }

    len = out->buffer_size;
    err = cbor_value_copy_byte_string(iter, out->buffer, &len, NULL);
    CHECK_CBOR_ERROR(err, result, exit);

    out->psbt_len = len;

exit:
    return result;
}
