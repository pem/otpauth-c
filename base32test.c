/*
** pem 2024-10-05
**
** Test program for the base32 functions in the otpauth-c library.
**
*/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <inttypes.h>

#include "otpauth.h"

static bool
check_bin(const uint8_t *val, size_t vallen,
          const uint8_t *exp, size_t explen)
{
    bool ret = true;

    if (vallen != explen)
    {
        fprintf(stderr, "### Length is %zu, expected %zu\n", vallen, explen);
        ret = false;
    }
    for (size_t i = 0 ; i < explen && i < vallen ; i++)
        if (val[i] != exp[i])
        {
            fprintf(stderr,
                    "### Difference in position %zu: %02" PRIx8
                    " != %02" PRIx8 "\n",
                    i, exp[i], val[i]);
            ret = false;
        }
    if (ret)
        printf("Ok\n");
    return ret;
}

static bool
check_string(const char *val, const char *exp)
{
    if (strcmp(val, exp) != 0)
    {
        fprintf(stderr, "### Expected %s, got %s\n", exp, val);
        return false;
    }
    printf("Ok\n");
    return true;
}

static bool
check_uint64(uint64_t val, uint64_t exp)
{
    if (val != exp)
    {
        fprintf(stderr, "### Expected %" PRIu64 ", got %" PRIu64 "\n",
                exp, val);
        return false;
    }
    printf("Ok\n");
    return true;
}

static bool
check_null(void *ptr)
{
    if (ptr != NULL)
    {
        fprintf(stderr, "### Expected NULL, got a pointer\n");
        return false;
    }
    printf("Ok\n");
    return true;
}

typedef struct test_s
{
    char *name;
    size_t len;
    uint8_t bin[32];
    char *exp;
} test_t;

static test_t Test_data[] =
    {
        { "Empty", 0, "", "" },
        { "f", 1, "f", "MY" },
        { "fo", 2, "fo", "MZXQ" },
        { "foo", 3, "foo", "MZXW6" },
        { "foob", 4, "foob", "MZXW6YQ" },
        { "fooba", 5, "fooba", "MZXW6YTB" },
        { "foobar", 6, "foobar", "MZXW6YTBOI" },
        { "00", 7, { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
                   "AAAAAAAAAAAA" },
        { "F0", 7, { 0xF0, 0xF0, 0xF0, 0xF0, 0xF0, 0xF0, 0xF0 },
                   "6DYPB4HQ6DYA" },
        { "0F", 7, { 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F },
                   "B4HQ6DYPB4HQ" },
        { "FF", 7, { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF },
                   "77777777777Q" },
        { "1-20", 20, { 1,  2,  3,  4,  5,  6,  7,  8,  9, 10,
                       11, 12, 13, 14, 15, 16, 17, 18, 19, 20 },
                      "AEBAGBAFAYDQQCIKBMGA2DQPCAIREEYU" },
        { "Long", 27, "A relatively longish string",
                      "IEQHEZLMMF2GS5TFNR4SA3DPNZTWS43IEBZXI4TJNZTQ" },
        { "Random", 16, { 0xad, 0xb0, 0x6d, 0xca, 0x76, 0x7d, 0xa4, 0x47,
                         0x67, 0xce, 0xc5, 0xb4, 0x3a, 0x29, 0x2a, 0x69 },
                        "VWYG3STWPWSEOZ6OYW2DUKJKNE" },
        { NULL }
    };

static test_t Bad_data[] =
    {
        { "Bad one char", 0, "", "X" },
        { "Bad char two", 0, "", "X9" },
        { "Bad char long", 0, "", "VWYG3STWPWSEOZ6OYW2DUKJK9E" },
        { "Lower case", 0, "", "vwyg3stwpwseoz6oyw2dukjkne" },
        { NULL }
    };

int
main(int argc, char **argv)
{
    bool ret = true;
    size_t b32len, binlen;
    char b32[BASE32_ENCODED_MIN_SIZE(32)];
    uint8_t bin[64];
    char *b32a;
    uint8_t *bina;

    printf("=== Encode error\n");
    printf("--- Test to nothing: ");
    b32len = base32encode((uint8_t *)"XYZ", 3, b32, 0);
    ret &= check_uint64(b32len, 0);
    printf("--- Test to too small: ");
    b32len = base32encode((uint8_t *)"ABCDEFGHIJKL", 12, b32,
                          BASE32_ENCODED_MIN_SIZE(12)-2);
    ret &= check_uint64(b32len, BASE32_ENCODED_MIN_SIZE(12)-2);

    printf("\n=== Decode error\n");
    printf("--- Test to nothing: ");
    binlen = base32decode("XYZ", bin, 0);
    ret &= check_uint64(binlen, 0);
    printf("--- Test to too small: ");
    binlen = base32decode("MZXW6YTBOI", bin, 4);
    ret &= check_uint64(binlen, 0);

    for (int i = 0 ; Bad_data[i].name != NULL ; i++)
    {
        printf("--- Test %s: ", Bad_data[i].name);
        binlen = base32decode(Bad_data[i].exp, bin, sizeof(bin));
        ret &= check_uint64(binlen, 0);
    }
    for (int i = 0 ; Bad_data[i].name != NULL ; i++)
    {
        printf("--- Test allocated %s: ", Bad_data[i].name);
        bina = base32decode_alloc(Bad_data[i].exp, &binlen);
        ret &= check_null(bina);
    }

    printf("\n=== Decode padding\n");
    printf("--- Test padding 1: ");
    binlen = base32decode("MZXW6YQ=", bin, sizeof(bin));
    ret &= check_bin(bin, binlen, (uint8_t *)"foob", 4);
    printf("--- Test padding 3: ");
    binlen = base32decode("MZXW6===", bin, sizeof(bin));
    ret &= check_bin(bin, binlen, (uint8_t *)"foo", 3);
    printf("--- Test padding 4: ");
    binlen = base32decode("MZXQ====", bin, sizeof(bin));
    ret &= check_bin(bin, binlen, (uint8_t *)"fo", 2);
    printf("--- Test padding 6: ");
    binlen = base32decode("MZXW6YTBOI======", bin, sizeof(bin));
    ret &= check_bin(bin, binlen, (uint8_t *)"foobar", 6);

    printf("\n=== In buffer\n");
    for (int i = 0 ; Test_data[i].name != NULL ; i++)
    {
        printf("--- Test %s encode: ", Test_data[i].name);
        b32len = base32encode(Test_data[i].bin, Test_data[i].len,
                              b32, sizeof(b32));
        ret &= check_string(b32, Test_data[i].exp);

        printf("--- Test %s decode: ", Test_data[i].name);
        binlen = base32decode(b32, bin, sizeof(bin));
        ret &= check_bin(bin, binlen, Test_data[i].bin, Test_data[i].len);
    }

    printf("\n=== Allocated\n");
    for (int i = 0 ; Test_data[i].name != NULL ; i++)
    {
        printf("--- Test %s encode: ", Test_data[i].name);
        b32a = base32encode_alloc(Test_data[i].bin, Test_data[i].len);
        ret &= check_string(b32a, Test_data[i].exp);

        bina = base32decode_alloc(b32a, &binlen);

        printf("--- Test %s decode: ", Test_data[i].name);
        ret &= check_bin(bina, binlen, Test_data[i].bin, Test_data[i].len);
        free(b32a);
        free(bina);
    }

    if (ret)
    {
        printf("\nTests passed\n");
        exit(0);
    }
    fprintf(stderr, "\n### Tests failed\n");
    exit(1);
}
