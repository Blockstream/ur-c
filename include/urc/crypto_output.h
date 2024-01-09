#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "urc/crypto_eckey.h"
#include "urc/crypto_hdkey.h"
#include "urc/error.h"

typedef struct {
    enum {
        keyexp_type_na,
        keyexp_type_pk,
        keyexp_type_pkh,
        keyexp_type_wpkh,
        keyexp_type_cosigner,
    } type;

    union {
        crypto_eckey eckey;
        crypto_hdkey hdkey;
    } key;
    enum {
        keyexp_keytype_na,
        keyexp_keytype_eckey,
        keyexp_keytype_hdkey,
    } keytype;
} output_keyexp;

#define URC_RAWSCRIPT_LEN 32
typedef struct {
    union {
        output_keyexp key; // p2pkh
        uint8_t raw[URC_RAWSCRIPT_LEN];
    } output;
    enum {
        output_type_na,
        output_type__, // p2pk, p2pkh, p2wpkh
        output_type_sh,
        output_type_wsh,
        output_type_sh_wsh,
        output_type_rawscript, // raw field
    } type;
} crypto_output;

int urc_crypto_output_deserialize(const uint8_t *cbor_buffer, size_t cbor_len, crypto_output *out);

typedef enum {
    // output descriptor represented as is
    urc_crypto_output_format_mode_default,
    // if derivation path is empty, and key origin counts to 2, an extra ``/0/*`` is added as derivation path
    urc_crypto_output_format_mode_BIP44_compatible,
} urc_crypto_output_format_mode;
// ``out`` must be freed by caller using urc_string_free function
int urc_crypto_output_format(const crypto_output *output, urc_crypto_output_format_mode mode, char **out);

#ifdef __cplusplus
}
#endif
