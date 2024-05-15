#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

#include "urc/error.h"

int urc_jade_rpc_deserialize(const uint8_t *cbor_buffer, size_t cbor_len, char **out);

#ifdef __cplusplus
}
#endif
