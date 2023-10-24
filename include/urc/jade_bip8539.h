#pragma once

#include <stdint.h>

#include "urc/crypto_eckey.h"
#include "urc/error.h"

typedef struct {
    // given the derivation path as described in BIP 85
    // m/83696968'/39'/{language}'/{num_words}'/{index}'
    // where language is the BIP 85 language code for english
    // num_words: either 12 or 24
    uint32_t num_words;
    uint32_t index;
    // public key of the ephemeral key used to encrypt the response
    uint8_t pubkey[CRYPTO_ECKEY_PUBLIC_COMPRESSED_SIZE];
} jade_bip8539_request;

typedef struct {
    // public key of the ephemeral key used to encrypt the response
    uint8_t pubkey[CRYPTO_ECKEY_PUBLIC_COMPRESSED_SIZE];
    // length of the encrypted data
    size_t encrypted_len;
    uint8_t *encripted_data;
} jade_bip8539_response;

int urc_jade_bip8539_request_format(const jade_bip8539_request *request, uint8_t *out, size_t *len);

// in case of no error, ``response->encrypted_data`` is going to point to ``buffer``
int urc_jade_bip8539_response_parse(const uint8_t *cbor, size_t cbor_len, jade_bip8539_response *response, uint8_t *buffer,
                                    size_t buffer_len);
