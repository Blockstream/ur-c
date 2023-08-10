
#include "internals.h"
#include "macros.h"
#include "utils.h"

bcr_error internal_parse_seed(CborValue *iter, crypto_seed *out) {
    bcr_error result = {.tag = bcr_error_tag_noerror};

    CHECK_IS_TYPE(iter, map, result, exit);

    CborValue item;
    CborError err;
    err = cbor_value_enter_container(iter, &item);
    CHECK_CBOR_ERROR(err, result, exit);

    result = check_map_key(&item, 1);
    if (result.tag != bcr_error_tag_noerror) {
        goto leave_and_exit;
    }

    ADVANCE(&item, result, leave_and_exit);

    result = copy_fixed_size_byte_string(&item, out->seed, CRYPTO_SEED_SIZE);
    if (result.tag != bcr_error_tag_noerror) {
        goto leave_and_exit;
    }

    if (cbor_value_at_end(&item)) {
        goto leave_and_exit;
    }

    ADVANCE(&item, result, leave_and_exit);

    result = check_map_key(&item, 2);
    if (result.tag != bcr_error_tag_noerror) {
        goto leave_and_exit;
    }

    ADVANCE(&item, result, leave_and_exit);

    result = check_tag(&item, 100); // TODO: check whether this is an official RFC 8949 tag or what
    if (result.tag != bcr_error_tag_noerror) {
        goto leave_and_exit;
    }

    err = cbor_value_skip_tag(&item);
    CHECK_CBOR_ERROR(err, result, leave_and_exit);

    err = cbor_value_get_uint64(&item, &out->creation_date);
    CHECK_CBOR_ERROR(err, result, leave_and_exit);

leave_and_exit:
    while (!cbor_value_at_end(&item)) {
        cbor_value_advance(&item);
    }
    err = cbor_value_leave_container(iter, &item);
    assert(err == CborNoError);
exit:
    return result;
}
