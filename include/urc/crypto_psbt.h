#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

#include "urc/error.h"

typedef struct {
    uint8_t *psbt;
    size_t psbt_len;

} crypto_psbt;

// ``out`` must be freed by caller using urc_crypto_psbt_free
int urc_crypto_psbt_deserialize(const uint8_t *cbor_buffer, size_t cbor_len, crypto_psbt *out);
int urc_crypto_psbt_serialize(const crypto_psbt *psbt, uint8_t **cbor_out, size_t *cbor_len);
void urc_crypto_psbt_free(crypto_psbt *psbt);

#ifdef __cplusplus
}
#endif
