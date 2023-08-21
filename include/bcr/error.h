
#pragma once

#include "tinycbor/cbor.h"

typedef enum bcr_error_tags {
    bcr_error_tag_noerror = 0,

    bcr_error_tag_cborinternalerror,
    bcr_error_tag_unhandledcase,
    bcr_error_tag_wrongtype,
    bcr_error_tag_wrongtag,
    bcr_error_tag_wrongmapkey,
    bcr_error_tag_wrongstringlength,
    bcr_error_tag_notimplementedurtype,
    bcr_error_tag_unknownformat,

} bcr_error_tags;

typedef struct bcr_error {
    union {
        CborError cbor;
    } internal;
    bcr_error_tags tag;
} bcr_error;
