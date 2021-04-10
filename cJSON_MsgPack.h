#ifndef cJSON_MsgPack__h
#define cJSON_MsgPack__h

#ifdef __cplusplus
extern "C"
{
#endif

#include "cJSON.h"
#include <stdint.h>

#define CJSON_MSGPACK_USE_SBUF
//#define CJSON_MSGPACK_USE_VREFBUF

CJSON_PUBLIC(char *) cJSON_PrintMsgPack(cJSON *item, size_t *size);
CJSON_PUBLIC(cJSON*) cJSON_ParseMsgPack(uint8_t *data, size_t length);

#ifdef __cplusplus
}
#endif

#endif