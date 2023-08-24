
#pragma once

#include "tinycbor/cbor.h"

typedef enum {
    urc_error_tag_noerror = 0,

    urc_error_tag_cborinternalerror,
    urc_error_tag_unhandledcase,
    urc_error_tag_wrongtype,
    urc_error_tag_wrongtag,
    urc_error_tag_wrongmapkey,
    urc_error_tag_wrongstringlength,
    urc_error_tag_notimplementedurtype,
    urc_error_tag_unknownformat,
    urc_error_tag_taprootnotsupported,

} urc_error_tags;

typedef struct {
    union {
        CborError cbor;
    } internal;
    urc_error_tags tag;
} urc_error;
