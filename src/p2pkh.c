
#include "internals.h"
#include "macros.h"
#include "utils.h"

bcr_error internal_parse_p2pkh(CborValue *iter, crypto_p2pkh *out) {
    out->key.type = uninitialized;
    bcr_error result = {.tag = bcr_error_tag_noerror};

    result = check_tag(iter, bcr_urtypes_tags_crypto_p2pkh);
    if (result.tag != bcr_error_tag_noerror) {
        goto exit;
    }

    ADVANCE(iter, result, exit);

    result = check_tag(iter, bcr_urtypes_tags_crypto_eckey);
    if (result.tag != bcr_error_tag_noerror) {
        goto exit;
    }

    ADVANCE(iter, result, exit);

    result = internal_parse_eckey(iter, &out->key);

exit:
    return result;
}
