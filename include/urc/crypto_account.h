#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "urc/crypto_output.h"
#include "urc/error.h"

#ifndef DESCRIPTORS_MAX_SIZE
#define DESCRIPTORS_MAX_SIZE 10
#endif
typedef struct {
    crypto_output descriptors[DESCRIPTORS_MAX_SIZE];
    size_t descriptors_count;
    uint32_t master_fingerprint;
} crypto_account;

// WARNING: taproot outpute descriptors are not yet supported
// when a taproot descriptor is found, this function skips it, carries on and collects the other descriptors

int urc_crypto_account_deserialize(const uint8_t *cbor_buffer, size_t cbor_len, crypto_account *out);
// parse an account in jade format, descriptors are not introduced by tag 308
int urc_jade_account_deserialize(const uint8_t *cbor_buffer, size_t len, crypto_account *out);

// *out[] must be freed using urc_string_array_free()
// last element of *out[] is NULL
int urc_crypto_account_format(const crypto_account *account, urc_crypto_output_format_mode mode, char **out[]);

#ifdef __cplusplus
}
#endif
