#pragma once

#define ADVANCE(cursor, urcerror, exit_point)                                                                          \
    {                                                                                                                  \
        CborError err = cbor_value_advance(cursor);                                                                    \
        if (err != CborNoError) {                                                                                      \
            urcerror.tag = urc_error_tag_cborinternalerror;                                                            \
            urcerror.internal.cbor = err;                                                                              \
            goto exit_point;                                                                                           \
        }                                                                                                              \
    }

#define CHECK_CBOR_ERROR(error, urcerror, exit_point)                                                                  \
    if (error != CborNoError) {                                                                                        \
        urcerror.tag = urc_error_tag_cborinternalerror;                                                                \
        urcerror.internal.cbor = error;                                                                                \
        goto exit_point;                                                                                               \
    }

#define CHECK_IS_TYPE(cursor, type, urcerror, exit_point)                                                              \
    if (!cbor_value_is_##type(cursor)) {                                                                               \
        urcerror.tag = urc_error_tag_wrongtype;                                                                        \
        goto exit_point;                                                                                               \
    }

#define LEAVE_CONTAINER_SAFELY(cursor, recursive, urcerror, exit_point)                                                           \
    if (!cbor_value_at_end(recursive)) {                                                                                  \
        urcerror.tag = urc_error_tag_unknownformat;                                                                    \
        goto exit_point;                                                                                               \
    }                                                                                                                  \
    {                                                                                                                  \
        err = cbor_value_leave_container(cursor, recursive);                                                                \
        if (err != CborNoError) {                                                                                      \
            urcerror.tag = urc_error_tag_cborinternalerror;                                                            \
            urcerror.internal.cbor = err;                                                                              \
            goto exit_point;                                                                                           \
        }                                                                                                              \
    }
