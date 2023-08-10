#pragma once

#include "tinycbor/cbor.h"

#include "bcr/bcr.h"

bcr_error internal_parse_seed(CborValue *iter, crypto_seed* out);
bcr_error internal_parse_psbt(CborValue *iter, crypto_psbt* out);
bcr_error internal_parse_eckey(CborValue *iter, crypto_eckey* out);
bcr_error internal_parse_p2pkh(CborValue *iter, crypto_p2pkh* out);
// bcr_error internal_parse_p2sh(CborValue *iter, crypto_p2sh* out);
bcr_error internal_parse_output(CborValue *iter, crypto_output* out);
