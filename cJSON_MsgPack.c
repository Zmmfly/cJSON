#include "cJSON_MsgPack.h"
#include "tiny_msgpk.h"
#include <math.h>

static char *format_string(const char *input);
int cJSON_msgpack(msgpk_t *pk, cJSON *root);
int cJSON_msgunpack(cJSON *root, msgpk_parse_t *parse, char *key);

/**
 * @brief 解析MsgPack
 * 
 * @param data[in] MsgPack数据指针
 * @param length[in] MsgPack数据长度
 * 
 */
CJSON_PUBLIC(cJSON*) cJSON_ParseMsgPack(uint8_t *data, size_t length)
{
    cJSON *root = NULL;
    int i = 0; size_t off = 0;
    msgpk_parse_t parse;
    msgpk_decode_t decode;

    msgpk_parse_init(&parse, data, length);

    if(!msgpk_parse_get(&parse, &decode))
    {
        if(decode.type_dec == MSGPK_MAP)
        {
            root = cJSON_CreateObject();
            cJSON_msgunpack(root, &parse, NULL);
        }
        else if(decode.type_dec == MSGPK_ARR)
        {
            root = cJSON_CreateArray();
            cJSON_msgunpack(root, &parse, "a");
        }
        else
        {
            goto exit;
        }
    }
exit:
    msgpk_parse_deinit(&parse);
    return root;
}

/**
 * @brief 输出MsgPack
 * 
 * @param item[in] cJSON节点
 * @param size[out] 输出的MsgPack长度
 * 
 * @return char * MsgPack, NULL为错误, 使用完成后需cJSON_free释放
 * 
 */
CJSON_PUBLIC(char *) cJSON_PrintMsgPack(cJSON *item, size_t *size)
{
    int result = -1;
    msgpk_t *pk;
    char *msgpk = NULL;
    if (size == NULL) return NULL;
    pk = msgpk_create(8, 4);

    if( (item == NULL) || (size == NULL) || (pk == NULL) ) return NULL;
    result = cJSON_msgpack(pk, item);
    if (result == -1) {
        msgpk_delete(pk, 1, 1);
        return NULL;
    }

    *size = pk->msgpk_sz;
    msgpk = (char *)pk->msgpk_buf;
    msgpk_delete(pk, 0, 1);
    return msgpk;
}

CJSON_PUBLIC(void) cJSON_DeleteMsgpk(void *msgpk)
{
    if (msgpk == NULL)return;
    msgpk_free(msgpk);
}

char *create_string(const char *ptr, size_t length)
{
    char *buf = cJSON_calloc(1, length + 1);
    if(buf == NULL) return NULL;
    memcpy(buf, ptr, length);
    return buf;
}

/**
 * @brief 解包MsgPack
 * 
 * @param root 
 * @param obj 
 * @param key 
 * @return int 
 */
int cJSON_msgunpack(cJSON *root, msgpk_parse_t *parse, char *key)
{
    // cJSON *item = NULL, *array = NULL, *object = NULL;
    union {
        cJSON *item;
        cJSON *array;
        cJSON *object;
    }cj;

    int            ret     = -1;
    char           *tmp    = NULL;
    msgpk_decode_t *decode = cJSON_calloc(1, sizeof(msgpk_decode_t));
    int64_t        i64     = 0;
    uint64_t       u64     = 0;

    if( (root == NULL) || (parse == NULL) || (decode == NULL) ){
        goto __exit;
    }

    if ( msgpk_parse_get(parse, decode) != 0) return -1;
    switch (decode->type_dec)
    {
        case MSGPK_NIL:
            if(key)
            {
                cJSON_AddNullToObject(root, key);
            }else
            {
                cj.item = cJSON_CreateNull();
                cJSON_AddItemToArray(root, cj.item);
            }
            break;

        case MSGPK_BOOL:
            if(key)
            {
                cJSON_AddBoolToObject(root, key, decode->boolean ? cJSON_True : cJSON_False);
            }else
            {
                cj.item = cJSON_CreateBool(decode->boolean ? cJSON_True : cJSON_False);
                cJSON_AddItemToArray(root, cj.item);
            }
            break;

        case MSGPK_UINT8:
            u64 = decode->u8;
            goto u64_decode;
        case MSGPK_UINT16:
            u64 = decode->u16;
            goto u64_decode;
        case MSGPK_UINT32:
            u64 = decode->u32;
            goto u64_decode;
        case MSGPK_UINT64:
            u64 = decode->u64;
            u64_decode:
            if(key)
            {
                cJSON_AddNumberToObject(root, key, u64);
            }else
            {
                cj.item = cJSON_CreateNumber(u64);
                cJSON_AddItemToArray(root, cj.item);
            }
            
            break;

        case MSGPK_INT8:
            i64 = decode->i8;
            goto i64_decode;

        case MSGPK_INT16:
            i64 = decode->i16;
            goto i64_decode;

        case MSGPK_INT32:
            i64 = decode->i32;
            goto i64_decode;

        case MSGPK_INT64:
            i64 = decode->i64;
            i64_decode:
            if(key)
            {
                cJSON_AddNumberToObject(root, key, i64);
            }else
            {
                cj.item = cJSON_CreateNumber(i64);
                cJSON_AddItemToArray(root, cj.item);
            }
            break;

        case MSGPK_FLOAT32:
            if(key)
            {
                cJSON_AddNumberToObject(root, key, decode->f32);
            }else
            {
                cj.item = cJSON_CreateNumber(decode->f32);
                cJSON_AddItemToArray(root, cj.item);
            }
            break;

        case MSGPK_FLOAT64 :
            if(key)
            {
                cJSON_AddNumberToObject(root, key, decode->f64);
            }else
            {
                cj.item = cJSON_CreateNumber(decode->f64);
                cJSON_AddItemToArray(root, cj.item);
            }
            break;

        case MSGPK_STRING:
            if(key)
            {
                tmp = create_string(decode->str, decode->length);
                cJSON_AddStringToObject(root, key, tmp);
                cJSON_free(tmp);
            }else
            {
                tmp = create_string(decode->str, decode->length);
                cj.item = cJSON_CreateString(tmp);
                cJSON_AddItemToArray(root, cj.item);
                cJSON_free(tmp);
            }
            break;

        case MSGPK_ARR:
            if(root->type == cJSON_Object)
            {
                if(key == NULL) goto __exit;
                cj.array = cJSON_AddArrayToObject(root, key);
            }
            else if( (root->type == cJSON_Array) && (key != NULL) )
            {
                cj.array = root;
            }
            else if( (root->type == cJSON_Array) && (key == NULL) )
            {
                cj.array = cJSON_CreateArray();
            }
            else
            {
                goto __exit;
            }
            
            if(cj.array == NULL) goto __exit;
            if(decode->length != 0)
            {
                for (size_t i=0; i<decode->length; i++)
                {
                    msgpk_parse_next(parse);
                    cJSON_msgunpack(cj.array, parse, NULL);
                }
            }

            if(root->type == cJSON_Array)
            {
                cJSON_AddItemToArray(root, cj.array);
            }
            
            break;

        case MSGPK_MAP:
            if(root->type == cJSON_Object)
            {
                if(key == NULL)
                {
                    cj.object = root;
                }else
                {
                    cj.object = cJSON_AddObjectToObject(root, key);
                }
                
            }
            else if(root->type == cJSON_Array)
            {
                cj.object = cJSON_CreateObject();
            }
            else
            {
                goto __exit;
            }

            if(cj.object == NULL) goto __exit;
            if(decode->length != 0)
            {
                for (size_t i=0,loop=decode->length; i<loop; i++)
                {
                    msgpk_parse_next(parse);
                    msgpk_parse_get(parse, decode);

                    if (decode->type_dec != MSGPK_STRING) goto __exit;
                    tmp = create_string(decode->str, decode->length);

                    msgpk_parse_next(parse);
                    cJSON_msgunpack(cj.object, parse, tmp);
                    cJSON_free(tmp);
                }
                
            }

            if(root->type == cJSON_Array)
            {
                cJSON_AddItemToArray(root, cj.object);
            }
            break;

        case MSGPK_BIN:
            if(key) {
                cJSON_AddBinToObject(root, key, (void *)decode->bin, decode->length);\
            } else {
                cj.item = cJSON_CreateBin((void *)decode->bin, decode->length);
                cJSON_AddItemToArray(root, cj.item);
            }
            break;

        case MSGPK_EXT:
            if(key) {
                cJSON_AddExtToObject(root, key, (void *)decode->bin, decode->length, decode->type_ext);
            } else {
                cj.item = cJSON_CreateExt((void *)decode->bin, decode->length, decode->type_ext);
                cJSON_AddItemToArray(root, cj.item);
            }
            break;

        default:
            goto __exit;
            break;
    }

    ret = 0;

__exit:
    if (decode != NULL)cJSON_free(decode);
    return ret;
}

int cJSON_msgpack(msgpk_t *pk, cJSON *root)
{
    int ret = 0;
    size_t sz = 0, i = 0;
    char *strval = NULL;
    cJSON *node;

    if(root == NULL || pk == NULL) return -1;
    switch (root->type & 0xff)
    {
        case cJSON_Invalid:
            ret = msgpk_add_nil(pk);
            break;

        case cJSON_False:
            ret = msgpk_add_false(pk);
            break;

        case cJSON_True:
            ret = msgpk_add_true(pk);
            break;

        case cJSON_NULL:
            ret = msgpk_add_nil(pk);
            break;

        case cJSON_String:
            strval = format_string(root->valuestring);
            ret = (strval != NULL) ? msgpk_add_str(pk, strval, strlen(strval)) : -1;
            if(strval) cJSON_free(strval);
            break;

        case cJSON_Number:
            if( isnan(root->valuedouble) || isinf(root->valuedouble) ) {
                ret = msgpk_add_nil(pk);
            } else if ( root->valuedouble == root->valueint ) {
                ret = msgpk_add_int(pk, root->valueint);
            } else {
                ret = msgpk_add_float64(pk, root->valuedouble);
            }
            break;

        case cJSON_Bin:
            if( root->binptr == NULL )
            {
                ret = -1;
                break;
            }
            ret = msgpk_add_bin(pk, (uint8_t *)root->binptr, root->binsize);
            break;

        case cJSON_Ext:
            if( root->binptr == NULL )
            {
                ret = -1;
                break;
            }
            ret = msgpk_add_ext(pk, root->extype, (uint8_t *)root->binptr, root->binsize);
            break;

        case cJSON_Array:
            sz = cJSON_GetArraySize(root);
            if(msgpk_add_arr(pk, sz) != 0) return -1;

            for ( i = 0; i < sz; i++)
            {
                if( cJSON_msgpack(pk, cJSON_GetArrayItem(root, i) ) != 0 ) return -1;
            }
            ret = 0;
            break;

        case cJSON_Object:
            sz = cJSON_GetArraySize(root);
            if(msgpk_add_map(pk,sz) != 0) return -1;

            for ( i = 0; i < sz; i++)
            {
                node = cJSON_GetArrayItem(root, i);
                strval = format_string(node->string);
                if(strval == NULL) return -1;

                //put key
                if( msgpk_add_str(pk, strval, strlen(strval)) != 0 )
                {
                    cJSON_free(strval);       
                    return -1;
                }
                cJSON_free(strval);

                //put value
                if( cJSON_msgpack(pk, node) != 0) return -1;
            }
            ret = 0;
            break;

        default:
            ret = -1;
    }
    return ret;
}

static char *format_string(const char *input)
{
    const char *inptr;
    char *output;
    char *outptr;
    size_t output_length = 0;
    /* numbers of additional characters*/
    size_t escape_characters = 0;

    if (input == NULL) {
        return NULL;
    }

    for (inptr = input; *inptr; inptr++) {
        switch (*inptr) {
        case '\"':
        case '\\':
        case '\b':
        case '\f':
        case '\n':
        case '\r':
        case '\t':
            /* one character escape sequence */
            escape_characters++;
            break;
        default:
            break;
        }
    }
    output_length = (size_t)(inptr - input) + escape_characters;

    output = (char *)cJSON_malloc(output_length + 1);
    if (output == NULL) {
        return NULL;
    }

    /* no add characters*/
    if (escape_characters == 0) {
        memcpy(output, input, output_length);
        output[output_length] = '\0';
        return output;
    }

    outptr = output;
    /* copy string */
    for (inptr = input; *inptr != '\0'; (void)inptr++, outptr++) {
        if ((*inptr > 31) && (*inptr != '\"') && (*inptr != '\\')) {
            /* normal character, copy */
            *outptr = *inptr;
        } else {
            /* character needs to be escaped */
            *outptr++ = '\\';
            switch (*inptr)
            {
            case '\\':
                *outptr = '\\';
                break;
            case '\"':
                *outptr = '\"';
                break;
            case '\b':
                *outptr = 'b';
                break;
            case '\f':
                *outptr = 'f';
                break;
            case '\n':
                *outptr = 'n';
                break;
            case '\r':
                *outptr = 'r';
                break;
            case '\t':
                *outptr = 't';
                break;
            default:
                break;
            }
        }
    }

    output[output_length] = '\0';
    return output;
}
