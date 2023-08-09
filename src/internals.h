#pragma once

#include "tinycbor/cbor.h"

#include "bcr/bcr.h"

bcr_error internal_parse_seed(CborValue *iter, crypto_seed* out);
bcr_error internal_parse_psbt(CborValue *iter, crypto_psbt* out);
bcr_error internal_parse_eckey(CborValue *iter, crypto_eckey* out);
