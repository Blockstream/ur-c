#pragma once

#define ADVANCE(cursor, urcerror, exit_point)                                                                                    \
    {                                                                                                                            \
        CborError err = cbor_value_advance(cursor);                                                                              \
        if (err != CborNoError) {                                                                                                \
            (urcerror) = URC_ECBORINTERNALERROR;                                                                                 \
            goto exit_point;                                                                                                     \
        }                                                                                                                        \
    }

#define CHECK_CBOR_ERROR(error, urcerror, exit_point)                                                                            \
    if ((error) != CborNoError) {                                                                                                \
        (urcerror) = URC_ECBORINTERNALERROR;                                                                                     \
        goto exit_point;                                                                                                         \
    }

#define CHECK_IS_TYPE(cursor, type, urcerror, exit_point)                                                                        \
    if (!cbor_value_is_##type(cursor)) {                                                                                         \
        (urcerror) = URC_EUNEXPECTEDTYPE;                                                                                        \
        goto exit_point;                                                                                                         \
    }

#define LEAVE_CONTAINER_SAFELY(cursor, recursive, urcerror, exit_point)                                                          \
    if (!cbor_value_at_end(recursive)) {                                                                                         \
        (urcerror) = URC_EUNKNOWNFORMAT;                                                                                         \
        goto exit_point;                                                                                                         \
    }                                                                                                                            \
    {                                                                                                                            \
        CborError err = cbor_value_leave_container(cursor, recursive);                                                           \
        if (err != CborNoError) {                                                                                                \
            (urcerror) = URC_ECBORINTERNALERROR;                                                                                 \
            goto exit_point;                                                                                                     \
        }                                                                                                                        \
    }

#define CHECK_WALLY_ERROR(error, urcerror, exit_point)                                                                           \
    if ((error) == WALLY_ENOMEM) {                                                                                               \
        (urcerror) = URC_ENOMEM;                                                                                                 \
        goto exit_point;                                                                                                         \
    }                                                                                                                            \
    if ((error) != WALLY_OK) {                                                                                                   \
        (urcerror) = URC_EWALLYINTERNALERROR;                                                                                    \
        goto exit_point;                                                                                                         \
    }
