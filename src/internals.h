#pragma once

#include "urc/error.h"
#include "urc/crypto_eckey.h"
#include "urc/crypto_hdkey.h"
#include "urc/crypto_output.h"


urc_error internal_parse_output(CborValue *iter, crypto_output *out);
urc_error internal_parse_eckey(CborValue *iter, crypto_eckey *out);
urc_error internal_parse_hdkey(CborValue *iter, crypto_hdkey *out);
