
#include "urc/crypto_seed.h"
#include "urc/tags.h"

#include "macros.h"
#include "utils.h"

int internal_parse_seed(CborValue *iter, crypto_seed *out);

int urc_crypto_seed_parse(const uint8_t *buffer, size_t len, crypto_seed *out) {
    CborParser parser;
    CborValue iter;
    CborError err;
    err = cbor_parser_init(buffer, len, cbor_flags, &parser, &iter);
    if (err != CborNoError) {
        int result = URC_ECBORINTERNALERROR;
        return result;
    }
    return internal_parse_seed(&iter, out);
}

int internal_parse_seed(CborValue *iter, crypto_seed *out) {
    int result = URC_OK;

    CHECK_IS_TYPE(iter, map, result, exit);

    CborValue item;
    CborError err;
    err = cbor_value_enter_container(iter, &item);
    CHECK_CBOR_ERROR(err, result, exit);

    result = check_map_key(&item, 1);
    if (result != URC_OK) {
        goto exit;
    }

    ADVANCE(&item, result, exit);

    result = copy_fixed_size_byte_string(&item, out->seed, CRYPTO_SEED_SIZE);
    if (result != URC_OK) {
        goto exit;
    }

    if (cbor_value_at_end(&item)) {
        goto leave_and_exit;
    }

    ADVANCE(&item, result, exit);

    result = check_map_key(&item, 2);
    if (result != URC_OK) {
        goto exit;
    }

    ADVANCE(&item, result, exit);

    result = check_tag(&item, CborNumberOfDaysSinceTheEpochDate19700101Tag);
    if (result != URC_OK) {
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
