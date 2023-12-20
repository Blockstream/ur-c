#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

#include "urc/error.h"

int urc_jade_rpc_parse(const uint8_t *cbor, size_t cbor_len, char **out);

#ifdef __cplusplus
}
#endif
