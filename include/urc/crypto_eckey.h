#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

#include "urc/error.h"

#define CRYPTO_ECKEY_PRIVATE_SIZE 32
#define CRYPTO_ECKEY_PUBLIC_COMPRESSED_SIZE 33
#define CRYPTO_ECKEY_PUBLIC_UNCOMPRESSED_SIZE 65

typedef struct {
    union {
        uint8_t prvate[CRYPTO_ECKEY_PRIVATE_SIZE];
        uint8_t public_compressed[CRYPTO_ECKEY_PUBLIC_COMPRESSED_SIZE];
        uint8_t public_uncompressed[CRYPTO_ECKEY_PUBLIC_UNCOMPRESSED_SIZE];
    } key;
    enum {
        eckey_type_na,
        eckey_type_private,
        eckey_type_public_compressed,
        eckey_type_public_uncompressed,
    } type;
} crypto_eckey;

int urc_crypto_eckey_deserialize(const uint8_t *cbor_buffer, size_t cbor_len, crypto_eckey *out);

#ifdef __cplusplus
}
#endif
