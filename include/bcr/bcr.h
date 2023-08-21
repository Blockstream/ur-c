#pragma once

#include <stdint.h>

#include "bcr/error.h"
#include "crypto_eckey.h"
#include "crypto_hdkey.h"
#include "crypto_psbt.h"
#include "crypto_seed.h"

typedef enum bcr_urtypes_tags {
    bcr_urtypes_tags_crypto_seed = 300,
    bcr_urtypes_tags_crypto_eckey = 306,
    bcr_urtypes_tags_crypto_psbt = 310,

    bcr_urtypes_tags_crypto_psh = 400,
    bcr_urtypes_tags_crypto_p2pkh = 403,
    bcr_urtypes_tags_crypto_p2wpkh = 404,
} bcr_tagged_types;


/////////////////////// crypto-output
/// p2pkh
// typedef struct crypto_p2pkh {
//     union {
//         crypto_eckey eckey;
//     } key;
//     enum p2pkh_type {
//         p2pkh_type_na,
//         p2pkh_type_eckey,
//     } type;
//
// } crypto_p2pkh;
//
// typedef struct crypto_output {
//     union {
//         crypto_p2pkh p2pkh;
//     } output;
//     enum output_type {
//         output_type_na,
//         output_type_p2pkh,
//     } type;
// } crypto_output;
// bcr_error parse_output(const uint8_t *buffer, unsigned int size, crypto_output *out);
