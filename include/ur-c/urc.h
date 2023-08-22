#pragma once

#include "ur-c/crypto_eckey.h"
#include "ur-c/crypto_hdkey.h"
#include "ur-c/crypto_psbt.h"
#include "ur-c/crypto_seed.h"
#include "ur-c/error.h"

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
// urc_error parse_output(const uint8_t *buffer, unsigned int size, crypto_output *out);
