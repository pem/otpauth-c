/*
** pem 2024-10-05
**
** See base32.h
**
*/

#include <stdlib.h>
#include <string.h>

#include "otpauth.h"

/* RFC 4648 §6 */
#define B32MAP "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

size_t
base32encode(const uint8_t *bin, size_t len, char *b32, size_t b32max)
{
    size_t j = 0;

    for (size_t i = 0 ; i < len ; i += 5)
    {
        /* Map from the number of binary bytes to the number of encoded
           characters. */
        static const int8_t map[] = { 0, 2, 4, 5, 7, 8 };
        size_t count = 5;

        if (len - i < 5)
            count = len - i;

        /* We use a copy of the chunk since might need an extra zero
           byte for bits "spilling over" at the end. */
        uint8_t b[6];
        memcpy(b, bin+i, count);
        b[count] = '\0';        /* Extra byte for trailing bits */

        int8_t c = map[count];

        /* 00000111 11222223 33334444 45555566 66677777 */
        if (c-- > 0 && j < b32max)
            b32[j++] = B32MAP[(b[0] >> 3) & 0x1F];    /* 0 */
        if (c-- > 0 && j < b32max)
            b32[j++] = B32MAP[((b[0] & 0x7) << 2) |   /* 1 */
                              ((b[1] >> 6) & 0x03)];
        if (c-- > 0 && j < b32max)
            b32[j++] = B32MAP[(b[1] >> 1) & 0x1F];    /* 2 */
        if (c-- > 0 && j < b32max)
            b32[j++] = B32MAP[((b[1] & 0x1) << 4) |   /* 3 */
                              ((b[2] >> 4) & 0x0F)];
        if (c-- > 0 && j < b32max)
            b32[j++] = B32MAP[((b[2] & 0xF) << 1) |   /* 4 */
                              ((b[3] >> 7) & 0x01)];
        if (c-- > 0 && j < b32max)
            b32[j++] = B32MAP[(b[3] >> 2) & 0x1F];    /* 5 */
        if (c-- > 0 && j < b32max)
            b32[j++] = B32MAP[((b[3] & 0x3) << 3) |   /* 6 */
                              ((b[4] >> 5) & 0x07)];
        if (c-- > 0 && j < b32max)
            b32[j++] = B32MAP[b[4] & 0x1F];           /* 7 */
    }
    if (j == b32max && j > 0)
        b32[j-1] = '\0';        /* Buffer too small */
    else if (b32max > 0)
        b32[j] = '\0';
    return j;
}

char *
base32encode_alloc(const uint8_t *bin, size_t binlen)
{
    size_t b32size = BASE32_ENCODED_MIN_SIZE(binlen)+1;
    char *b32 = malloc(b32size);

    if (b32 != NULL)
        base32encode(bin, binlen, b32, b32size);
    return b32;
}

size_t
base32decode(const char *b32, uint8_t *bin, size_t binmax)
{
    size_t j = 0;

    /* We stop at '=' padding as well */
    for (size_t i = 0 ; b32[i] != '\0' && b32[i] != '=' ; i++)
    {
        uint8_t b;
        char c = b32[i];

        if ('A' <= c && c <= 'Z')
            b = (c - 'A');
        else if ('2' <= c && c <= '7')
            b = (c - '2') + 26;
        else
            return 0;

        /* 00000111 11222223 33334444 45555566 66677777 */
        size_t off = i & 0x7;
        switch (off)
        {
        case 0:
            if (j >= binmax) return 0;
            bin[j] = b << 3;
            continue;
        case 1:
            if (j >= binmax-1) return 0;
            bin[j++] |= (b >> 2) & 0x7;
            bin[j] = (b << 6);
            continue;
        case 2:
            if (j >= binmax) return 0;
            bin[j] |= (b << 1);
            continue;
        case 3:
            if (j >= binmax-1) return 0;
            bin[j++] |= (b >> 4) & 0x1;
            bin[j] = (b << 4);
            continue;
        case 4:
            if (j >= binmax-1) return 0;
            bin[j++] |= (b >> 1) & 0xF;
            bin[j] = (b << 7);
            continue;
        case 5:
            if (j >= binmax) return 0;
            bin[j] |= (b << 2);
            continue;
        case 6:
            if (j >= binmax-1) return 0;
            bin[j++] |= (b >> 3) & 0x3;
            bin[j] = (b << 5);
            continue;
        case 7:
            if (j >= binmax) return 0;
            bin[j++] |= b;
        }
    }
    return j;
}

uint8_t *
base32decode_alloc(const char *b32, size_t *lenp)
{
    size_t binsize = (strlen(b32)*5)/8 + 1;
    uint8_t *bin = malloc(binsize);

    if (bin != NULL)
    {
        size_t b32len = base32decode(b32, bin, binsize);

        if (b32len == 0 && b32[0] != '\0')
        {                       /* Non-empty string returned nothing */
            free(bin);
            return NULL;
        }
        if (lenp != NULL)
            *lenp = b32len;
    }
    return bin;
}
