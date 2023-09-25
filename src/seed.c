
#include "cbor.h"

#include "urc/crypto_seed.h"

#include "macros.h"
#include "utils.h"

urc_error internal_parse_seed(CborValue *iter, crypto_seed *out);

urc_error parse_seed(size_t size, const uint8_t *buffer, crypto_seed *out) {
    CborParser parser;
    CborValue iter;
    CborError err;
    err = cbor_parser_init(buffer, size, cbor_flags, &parser, &iter);
    if (err != CborNoError) {
        urc_error result = {.tag = urc_error_tag_cborinternalerror, .internal.cbor = err};
        return result;
    }
    return internal_parse_seed(&iter, out);
}

urc_error internal_parse_seed(CborValue *iter, crypto_seed *out) {
    urc_error result = {.tag = urc_error_tag_noerror};

    CHECK_IS_TYPE(iter, map, result, exit);

    CborValue item;
    CborError err;
    err = cbor_value_enter_container(iter, &item);
    CHECK_CBOR_ERROR(err, result, exit);

    result = check_map_key(&item, 1);
    if (result.tag != urc_error_tag_noerror) {
        goto exit;
    }

    ADVANCE(&item, result, exit);

    result = copy_fixed_size_byte_string(&item, out->seed, CRYPTO_SEED_SIZE);
    if (result.tag != urc_error_tag_noerror) {
        goto exit;
    }

    if (cbor_value_at_end(&item)) {
        goto leave_and_exit;
    }

    ADVANCE(&item, result, exit);

    result = check_map_key(&item, 2);
    if (result.tag != urc_error_tag_noerror) {
        goto exit;
    }

    ADVANCE(&item, result, exit);

    result = check_tag(&item, 100); // TODO: check whether this is an official RFC 8949 tag or what
    if (result.tag != urc_error_tag_noerror) {
        goto exit;
    }

    err = cbor_value_skip_tag(&item);
    CHECK_CBOR_ERROR(err, result, exit);

    err = cbor_value_get_uint64(&item, &out->creation_date);
    CHECK_CBOR_ERROR(err, result, exit);

    ADVANCE(&item, result, exit);

leave_and_exit:
    LEAVE_CONTAINER_SAFELY(iter, &item, result, exit)

exit:
    return result;
}
