#pragma once

#include "cbor.h"

#include "urc/error.h"
#include "urc/crypto_eckey.h"
#include "urc/crypto_hdkey.h"
#include "urc/crypto_output.h"


int urc_crypto_output_parse_impl(CborValue *iter, crypto_output *out);
int urc_crypto_eckey_parse_impl(CborValue *iter, crypto_eckey *out);
int urc_crypto_hdkey_parse_impl(CborValue *iter, crypto_hdkey *out);

uint32_t urc_hdkey_getversion (const crypto_hdkey *hdkey);
uint8_t urc_hdkey_getdepth(const crypto_hdkey *hdkey);
uint32_t urc_hdkey_getchildnumber(const crypto_hdkey *hdkey);
uint8_t *urc_hdkey_getchaincode(const crypto_hdkey *hdkey);
uint8_t *urc_hdkey_getkeydata(const crypto_hdkey *hdkey);
uint32_t urc_hdkey_getparentfingerprint(const crypto_hdkey *hdkey);
