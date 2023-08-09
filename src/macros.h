#pragma once


#define ADVANCE(cursor, bcrerror, exit_point)                                                                          \
{                                                                                                                  \
    CborError err = cbor_value_advance(&cursor);                                                                   \
    if (err != CborNoError) {                                                                                      \
        bcrerror.tag = bcr_error_tag_cborinternalerror;                                                            \
        bcrerror.internal.cbor = err;                                                                              \
        goto exit_point;                                                                                           \
    }                                                                                                              \
}

#define CHECK_CBOR_ERROR(error, bcrerror, exit_point)                                                                  \
    if (error != CborNoError) {                                                                                    \
        bcrerror.tag = bcr_error_tag_cborinternalerror;                                                            \
        bcrerror.internal.cbor = error;                                                                            \
        goto exit_point;                                                                                           \
    }                                                                                                              \


