
#include "internals.h"
#include "macros.h"
#include "utils.h"
#include <tinycbor/cbor.h>

bcr_error internal_parse_output(CborValue *iter, crypto_output *out) {
    out->type = output_type_na;
    bcr_error result = {.tag = bcr_error_tag_noerror};

    CHECK_IS_TYPE(iter, tag, result, exit);

    CborTag tag;
    CborError err = cbor_value_get_tag(iter, &tag);
    CHECK_CBOR_ERROR(err, result, exit);

    switch (tag) {
        case bcr_urtypes_tags_crypto_p2pkh:
            out->type = output_type_p2pkh;

            ADVANCE(iter, result, exit);

            result = internal_parse_p2pkh(iter, &out->output.p2pkh);
            break;
        case bcr_urtypes_tags_crypto_psh:
        default:
            result.tag = bcr_error_tag_unhandledcase;
    }
exit:
    return result;
}
