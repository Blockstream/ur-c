#pragma once

#include <stdint.h>

#include "urc/crypto_eckey.h"
#include "urc/error.h"

typedef struct {
    unsigned int words;
    unsigned int index;
    uint8_t pubkey[CRYPTO_ECKEY_PUBLIC_COMPRESSED_SIZE];
} jade_request;

typedef struct {
    uint8_t pubkey[CRYPTO_ECKEY_PUBLIC_COMPRESSED_SIZE];
    size_t buffer_size;
    size_t encrypted_len;
    uint8_t *buffer;
} jade_response;

#ifdef WALLYFIED

// out must be freed by caller through wally APIs
urc_error format_jaderequest(const jade_request *request, size_t *size, uint8_t **out);
// out->buffer must be freed by caller through wally APIs
urc_error parse_jaderesponse(size_t size, const uint8_t *buffer, jade_response *out);

#else

// if buffer isn't large enough, the urc_error returns an internal CborError of type
// ``CborErrorOutOfMemory``
urc_error format_jaderequest(const jade_request *request, size_t size, uint8_t *out);

// response struct is expected to be filled with info about the buffer for the encrypted data
// i.e. ``buffer`` and ``buffer_size``
// if buffer isn't large enough, the urc_error returns an internal CborError of type 
// ``CborErrorOutOfMemory``
urc_error parse_jaderesponse(size_t size, const uint8_t *buffer, jade_response *out);

#endif
