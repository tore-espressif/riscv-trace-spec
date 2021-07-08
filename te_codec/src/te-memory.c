#include "te-memory.h"
#include "stdlib.h"
#include "string.h"
#include "assert.h"

void membuf_init(
    membuf_t *buf)
{
    buf = malloc(sizeof(membuf_t));
    assert(buf);
    buf->data = NULL;
    buf->data_len = 0;
}

size_t membuf_append(
    membuf_t *buf,
    size_t length,
    const void *data)
{
    buf->data = realloc(buf->data, buf->data_len + length);
    assert(buf->data);
    //@todo not used by te-elf-dis.c
    //memcpy(&buf->data[buf->data_len], data, length);
    buf->data_len += length;
    return length;
}

void membuf_free(
    membuf_t *buf)
{
    free(buf->data);
    //free(buf);
}

/*
 * wrapper for strdup() ... but exit() if it fails
 */
char *strdup_or_die(
    const char *str)
{
    char *s2 = strdup(str);
    assert(strcmp(str, s2) == 0);
    return s2;
}