#pragma once

#include "stdint.h"

#include "tinycbor/cbor.h"
#include <stdint.h>

typedef enum bcr_error_tags {
    bcr_error_tag_noerror = 0,

    bcr_error_tag_cborinternalerror,
    bcr_error_tag_unhandledcase,
    bcr_error_tag_wrongtype,
    bcr_error_tag_wrongtag,
    bcr_error_tag_wrongmapkey,
    bcr_error_tag_wrongstringlength,
    bcr_error_tag_notimplementedurtype,

} bcr_error_tags;

typedef struct bcr_error {
    union {
        CborError cbor;
    } internal;
    bcr_error_tags tag;
} bcr_error;

typedef enum bcr_urtypes_tags {
    bcr_urtypes_tags_crypto_seed = 300,
    bcr_urtypes_tags_crypto_eckey = 306,
    bcr_urtypes_tags_crypto_psbt = 310,
    bcr_urtypes_tags_crypto_p2pkh = 403,
} bcr_tagged_types;


/////////////////////// crypto-seed
#define CRYPTO_SEED_SIZE 16
typedef struct crypto_seed {
    uint8_t seed[CRYPTO_SEED_SIZE];
    uint64_t creation_date;

} crypto_seed;
bcr_error parse_seed(const uint8_t *buffer, unsigned int size, crypto_seed *out);

/////////////////////// crypto-psbt
typedef struct crypto_psbt {
    uint8_t *buffer;
    size_t buffer_size;
    size_t psbt_len;

} crypto_psbt;
bcr_error parse_psbt(const uint8_t *buffer, unsigned int size, crypto_psbt *out);

/////////////////////// crypto-eckey
#define CRYPTO_ECKEY_PRIVATE_SIZE 32
#define CRYPTO_ECKEY_PUBLIC_COMPRESSED_SIZE 33
#define CRYPTO_ECKEY_PUBLIC_UNCOMPRESSED_SIZE 64
typedef struct crypto_eckey {
    union {
        uint8_t private[CRYPTO_ECKEY_PRIVATE_SIZE];
        uint8_t public_compressed[CRYPTO_ECKEY_PUBLIC_COMPRESSED_SIZE];
        uint8_t public_uncompressed[CRYPTO_ECKEY_PUBLIC_UNCOMPRESSED_SIZE];
    } key;
    enum key_type {
        uninitialized,
        key_type_private,
        key_type_public_compressed,
        key_type_public_uncompressed,
    } type;
} crypto_eckey;
bcr_error parse_eckey(const uint8_t *buffer, unsigned int size, crypto_eckey *out);

/////////////////////// crypto-eckey
typedef struct crypto_p2pkh {
    crypto_eckey key;
} crypto_p2pkh;
bcr_error parse_p2pkh(const uint8_t *buffer, unsigned int size, crypto_p2pkh *out);
