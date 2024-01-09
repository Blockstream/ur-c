#pragma once

#ifdef __cplusplus
extern "C" {
#endif

void urc_free(void *ptr);
void urc_string_free(char *str);
void urc_string_array_free(char *str_array[]);

#ifdef __cplusplus
}
#endif
