#pragma once

#include "cbor.h"

#include "urc/error.h"
#include "urc/crypto_eckey.h"
#include "urc/crypto_hdkey.h"
#include "urc/crypto_output.h"


int urc_crypto_output_parse_impl(CborValue *iter, crypto_output *out);
int urc_crypto_eckey_parse_impl(CborValue *iter, crypto_eckey *out);
int urc_crypto_hdkey_parse_impl(CborValue *iter, crypto_hdkey *out);
