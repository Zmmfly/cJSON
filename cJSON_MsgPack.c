#include "cJSON_MsgPack.h"
#include "msgpack.h"
#include <math.h>

static char *format_string(const char *input);
int cJSON_msgpack(msgpack_packer *pk, cJSON *root);
int cJSON_msgunpack(cJSON *root, msgpack_object msgobj, char *key);

/**
 * @brief 解析MsgPack
 * 
 * @param data[in] MsgPack数据指针
 * @param length[in] MsgPack数据长度
 * 
 */
CJSON_PUBLIC(cJSON*) cJSON_ParseMsgPack(char *data, size_t length)
{
    cJSON *root = NULL;
    msgpack_unpacked unpack_result;
    msgpack_unpack_return unpack_ret;
    int i = 0; size_t off = 0;
    msgpack_unpacked_init(&unpack_result);

    unpack_ret = msgpack_unpack_next(&unpack_result, data, length, &off);
    if(unpack_ret == MSGPACK_UNPACK_SUCCESS)
    {
        // printf("unpack success\n");
        msgpack_object obj = unpack_result.data;
        if(obj.type == MSGPACK_OBJECT_MAP)
        {
            // printf("unpack map\n");
            root = cJSON_CreateObject();
            cJSON_msgunpack(root, obj, NULL);
        }
        else if(obj.type == MSGPACK_OBJECT_ARRAY)
        {
            // printf("unpack array\n");
            root = cJSON_CreateArray();
            cJSON_msgunpack(root, obj, "a");
        }
        else
        {
            goto exit;
        }
    }
exit:
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
    msgpack_sbuffer sbuf;
    msgpack_packer pk;
    if( (item == NULL) || (size == NULL) ) return NULL;

    msgpack_sbuffer_init(&sbuf);
    msgpack_packer_init(&pk, &sbuf, msgpack_sbuffer_write);

    result = cJSON_msgpack(&pk, item);

    if( (result != 0) && (sbuf.data != NULL) )
    {
        msgpack_sbuffer_destroy(&sbuf);
    }
    *size = sbuf.size;
    return sbuf.data;
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
int cJSON_msgunpack(cJSON *root, msgpack_object msgobj, char *key)
{
    cJSON *item = NULL, *array = NULL, *object = NULL;
    char *tmp = NULL;

    if(root == NULL){
        return -1;
    }
    switch (msgobj.type)
    {
        case MSGPACK_OBJECT_NIL:
            if(key)
            {
                cJSON_AddNullToObject(root, key);
            }else
            {
                item = cJSON_CreateNull();
                cJSON_AddItemToArray(root, item);
            }
            
            break;

        case MSGPACK_OBJECT_BOOLEAN:
            if(key)
            {
                cJSON_AddBoolToObject(root, key, msgobj.via.boolean ? cJSON_True : cJSON_False);
            }else
            {
                item = cJSON_CreateBool(msgobj.via.boolean ? cJSON_True : cJSON_False);
                cJSON_AddItemToArray(root, item);
            }
            break;

        case MSGPACK_OBJECT_POSITIVE_INTEGER:
            if(key)
            {
                cJSON_AddNumberToObject(root, key, msgobj.via.u64);
            }else
            {
                item = cJSON_CreateNumber(msgobj.via.u64);
                cJSON_AddItemToArray(root, item);
            }
            
            break;

        case MSGPACK_OBJECT_NEGATIVE_INTEGER:
            if(key)
            {
                cJSON_AddNumberToObject(root, key, msgobj.via.i64);
            }else
            {
                item = cJSON_CreateNumber(msgobj.via.i64);
                cJSON_AddItemToArray(root, item);
            }
            break;

        case MSGPACK_OBJECT_FLOAT32:
        case MSGPACK_OBJECT_FLOAT64 :
            if(key)
            {
                cJSON_AddNumberToObject(root, key, msgobj.via.f64);
            }else
            {
                item = cJSON_CreateNumber(msgobj.via.f64);
                cJSON_AddItemToArray(root, item);
            }
            break;

        case MSGPACK_OBJECT_STR:
            if(key)
            {
                tmp = create_string(msgobj.via.str.ptr, msgobj.via.str.size);
                cJSON_AddStringToObject(root, key, tmp);
                cJSON_free(tmp);
            }else
            {
                tmp = create_string(msgobj.via.str.ptr, msgobj.via.str.size);
                item = cJSON_CreateString(tmp);
                cJSON_AddItemToArray(root, item);
                cJSON_free(tmp);
            }
            break;

        case MSGPACK_OBJECT_ARRAY:
            if(root->type == cJSON_Object)
            {
                if(key == NULL) return -1;
                array = cJSON_AddArrayToObject(root, key);
            }
            else if( (root->type == cJSON_Array) && (key != NULL) )
            {
                array = root;
            }
            else if( (root->type == cJSON_Array) && (key == NULL) )
            {
                array = cJSON_CreateArray();
            }
            
            else
            {
                return -1;
            }
            
            if(array == NULL) return -1;
            if(msgobj.via.array.size != 0)
            {
                msgpack_object *p = msgobj.via.array.ptr;
                msgpack_object *const pend = msgobj.via.array.ptr + msgobj.via.array.size;
                for (; p < pend; p++)
                {
                    cJSON_msgunpack(array, *p, NULL);
                }
            }

            if(root->type == cJSON_Array)
            {
                cJSON_AddItemToArray(root, array);
            }
            
            break;

        case MSGPACK_OBJECT_MAP:
            // printf("object map proccess\n");
            if(root->type == cJSON_Object)
            {
                if(key == NULL)
                {
                    object = root;
                }else
                {
                    object = cJSON_AddObjectToObject(root, key);
                }
                
            }
            else if(root->type == cJSON_Array)
            {
                object = cJSON_CreateObject();
            }
            else
            {
                return -1;
            }

            if(object == NULL) return -1;
            if(msgobj.via.map.size != 0)
            {
                msgpack_object_kv *p = msgobj.via.map.ptr;
                msgpack_object_kv *const pend = msgobj.via.map.ptr + msgobj.via.map.size;
                for (; p < pend; p++)
                {
                    /* The key must be string */
                    if(p->key.type != MSGPACK_OBJECT_STR) return -1;
                    tmp = create_string(p->key.via.str.ptr, p->key.via.str.size);
                    // printf("map, key str:%s\n", tmp);
                    cJSON_msgunpack(object, p->val, tmp);
                    cJSON_free(tmp);
                }
                
            }

            if(root->type == cJSON_Array)
            {
                cJSON_AddItemToArray(root, object);
            }
            break;

        case MSGPACK_OBJECT_BIN:
            if(key) {
                cJSON_AddBinToObject(root, key, msgobj.via.bin.ptr, msgobj.via.bin.size);\
            } else {
                item = cJSON_CreateBin(msgobj.via.bin.ptr, msgobj.via.bin.size);
                cJSON_AddItemToArray(root, item);
            }
            break;

        case MSGPACK_OBJECT_EXT:
            if(key) {
                cJSON_AddExtToObject(root, key, msgobj.via.ext.ptr, msgobj.via.ext.size, msgobj.via.ext.type);
            } else {
                item = cJSON_CreateExt(msgobj.via.ext.ptr, msgobj.via.ext.size, msgobj.via.ext.type);
                cJSON_AddItemToArray(root, item);
            }
            break;

        default:
            return -1;
            break;
    }
    return 0;
}

int cJSON_msgpack(msgpack_packer *pk, cJSON *root)
{
    int ret = 0;
    size_t sz = 0, i = 0;
    char *strval = NULL;
    cJSON *node;

    if(root == NULL) return -1;

    switch (root->type & 0xff)
    {
        case cJSON_Invalid:
            ret = -1;
            break;

        case cJSON_False:
            ret = msgpack_pack_false(pk);
            break;

        case cJSON_True:
            ret = msgpack_pack_true(pk);
            break;

        case cJSON_NULL:
            ret = msgpack_pack_nil(pk);
            break;

        case cJSON_String:
            strval = format_string(root->valuestring);
            ret = (strval != NULL) ? msgpack_pack_str_with_body(pk, strval, strlen(strval)) : -1;
            if(strval) cJSON_free(strval);
            break;

        case cJSON_Number:
            if( isnan(root->valuedouble) || isinf(root->valuedouble) ) {
                ret = msgpack_pack_nil(pk);
            } else if ( root->valuedouble == root->valueint ) {
                ret = msgpack_pack_int(pk, root->valueint);
            } else {
                ret = msgpack_pack_double(pk, root->valuedouble);
            }
            break;

        case cJSON_Bin:
            if( root->binptr == NULL )
            {
                ret = -1;
                break;
            }
            ret = msgpack_pack_bin_with_body(pk, root->binptr, root->binsize);
            break;

        case cJSON_Ext:
            if( root->binptr == NULL )
            {
                ret = -1;
                break;
            }
            ret = msgpack_pack_ext_with_body(pk, root->binptr, root->binsize, root->extype);
            break;

        case cJSON_Array:
            sz = cJSON_GetArraySize(root);
            if(msgpack_pack_array(pk, sz) != 0) return -1;

            for ( i = 0; i < sz; i++)
            {
                if( cJSON_msgpack(pk, cJSON_GetArrayItem(root, i) ) != 0 ) return -1;
            }
            ret = 0;
            break;

        case cJSON_Object:
            sz = cJSON_GetArraySize(root);
            if( msgpack_pack_map(pk,sz) != 0 ) return -1;

            for ( i = 0; i < sz; i++)
            {
                node = cJSON_GetArrayItem(root, i);
                strval = format_string(node->string);
                if(strval == NULL) return -1;

                //put key
                if( msgpack_pack_str_with_body(pk, strval, strlen(strval)) != 0 )
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

