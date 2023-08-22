
#include "urc/urc.h"
#include "internals.h"
#include "macros.h"
#include "utils.h"

urc_error internal_parse_p2pkh(CborValue *iter, crypto_p2pkh *out) {
    out->type = p2pkh_type_na;
    urc_error result = {.tag = urc_error_tag_noerror};

    result = check_tag(iter, urc_urtypes_tags_crypto_eckey);
    if (result.tag != urc_error_tag_noerror) {
        goto exit;
    }

    ADVANCE(iter, result, exit);

    out->type = p2pkh_type_eckey;
    result = internal_parse_eckey(iter, &out->key.eckey);

exit:
    return result;
}
