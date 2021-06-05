#ifndef cJSON_MsgPack__h
#define cJSON_MsgPack__h

#ifdef __cplusplus
extern "C"
{
#endif

#include "cJSON.h"
#include <stdint.h>

#ifndef cJSON_FILE_ENABLE
#define cJSON_FILE_ENABLE   1
#endif


CJSON_PUBLIC(char *) cJSON_PrintMsgPack(cJSON *item, size_t *size);
CJSON_PUBLIC(cJSON*) cJSON_ParseMsgPack(uint8_t *data, size_t length);

#if cJSON_FILE_ENABLE
CJSON_PUBLIC(cJSON_bool) cJSON_PrintMsgPack_to_file(const char *path, cJSON *item);
CJSON_PUBLIC(cJSON*) cJSON_ParseMsgPack_from_file(const char *path);
#endif

CJSON_PUBLIC(void) cJSON_DeleteMsgpk(void *msgpk);

#ifdef __cplusplus
}
#endif

#endif