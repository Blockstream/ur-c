
#pragma once

#include "cbor.h"

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


#define URC_OK 0
#define URC_ECBORINTERNALERROR 1
#define URC_EUNHANDLEDCASE 2
#define URC_EUNEXPECTEDTYPE 3
#define URC_EUNEXPECTEDTAG 4
#define URC_EUNEXPECTEDMAPKEY 5
#define URC_EUNEXPECTEDSTRINGLENGTH 6
#define URC_EUNIMPLEMENTEDURTYPE 7
#define URC_EUNKNOWNFORMAT 8
#define URC_ETAPROOTNOTSUPPORTED 9
#define URC_EBUFFERTOOSMALL 10
