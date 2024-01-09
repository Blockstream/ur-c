#pragma once

#include "cbor.h"

#include "urc/crypto_eckey.h"
#include "urc/crypto_hdkey.h"
#include "urc/crypto_output.h"

int urc_crypto_output_deserialize_impl(CborValue *iter, crypto_output *out);
int urc_crypto_eckey_deserialize_impl(CborValue *iter, crypto_eckey *out);
int urc_crypto_hdkey_deserialize_impl(CborValue *iter, crypto_hdkey *out);

int urc_hdkey_getversion(const crypto_hdkey *hdkey, uint32_t *out);
int urc_hdkey_getdepth(const crypto_hdkey *hdkey, uint8_t *out);
int urc_hdkey_getkeyorigin_levels(const crypto_hdkey *hdkey, size_t *out);
int urc_hdkey_getchildnumber(const crypto_hdkey *hdkey, uint32_t *out);
int urc_hdkey_getchaincode(const crypto_hdkey *hdkey, uint8_t **out);
int urc_hdkey_getkeydata(const crypto_hdkey *hdkey, uint8_t **out);
int urc_hdkey_getparentfingerprint(const crypto_hdkey *hdkey, uint32_t *out);

int format_keyorigin(const crypto_hdkey *hdkey, char *out, size_t out_len);
int format_keyderivationpath(const crypto_hdkey *hdkey, char *out, size_t out_len);
