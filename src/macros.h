#pragma once

#define ADVANCE(cursor, bcrerror, exit_point)                                                                          \
    {                                                                                                                  \
        CborError err = cbor_value_advance(cursor);                                                                   \
        if (err != CborNoError) {                                                                                      \
            bcrerror.tag = bcr_error_tag_cborinternalerror;                                                            \
            bcrerror.internal.cbor = err;                                                                              \
            goto exit_point;                                                                                           \
        }                                                                                                              \
    }

#define CHECK_CBOR_ERROR(error, bcrerror, exit_point)                                                                  \
    if (error != CborNoError) {                                                                                        \
        bcrerror.tag = bcr_error_tag_cborinternalerror;                                                                \
        bcrerror.internal.cbor = error;                                                                                \
        goto exit_point;                                                                                               \
    }

#define CHECK_IS_TYPE(cursor, type, bcrerror, exit_point)                                                              \
    if (!cbor_value_is_##type(cursor)) {                                                                               \
        bcrerror.tag = bcr_error_tag_wrongtype;                                                                        \
        goto exit_point;                                                                                               \
    }
