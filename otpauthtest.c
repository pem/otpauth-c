/*
** pem 2024-10-07
**
** Test program for the otpauth functions in the otpauth-c library.
**
*/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <inttypes.h>

#include "otpauth.h"

static const char *
map_ret_code(otpauth_ret_t ret)
{
    switch (ret)
    {
    case otpauth_ok:
        return "ok";
    case otpauth_ekey:
        return "ekey";
    case otpauth_eb32:
        return "eb32";
    case otpauth_ehmac:
        return "ehmac";
    case otpauth_epar:
        return "epar";
    default:
        return "unknown";
    }
}

typedef struct test_s
{
    char *name;
    uint64_t counter;
    char *secret;
    uint8_t digits, period;
    char *algorithm;
    otpauth_ret_t ret;
    char *hotp, *totp;
} test_t;

static test_t HOTP_data[] =
    {
        { "Empty", 0, "", 6, 0, "SHA1", otpauth_ekey, "", "" },
        { "One", 0, "X",  6, 0, "SHA1", otpauth_eb32, "", "" },
        { "15", 0, "MFRGGZDFMZTWQ2LKNNWG23TP", 6, 0, "SHA1", otpauth_ekey, "", "" },
        { "16", 0, "MFRGGZDFMZTWQ2LKNNWG23TPOA", 6, 0, "SHA1", otpauth_ok, "874353", "" },
        { "Bad - B32 digit", 42, "MFRGGZDFMZTWQ2LKNNWG29TPOA", 6, 0, "SHA1", otpauth_eb32, "", "" },
        { "Bad - lowercase", 42, "mfrggzdfmztwq2lknnwg23tpoa", 6, 0, "SHA1", otpauth_eb32, "", "" },
        { "Bad - unknown hash", 1728577470, "CU55SBHBOSBBV6QCBKXVLDMMRA", 4, 0, "owueolj", otpauth_ehmac, "", "" },

        { "hotp-10-26-4-SHA1", 1728577470, "CU55SBHBOSBBV6QCBKXVLDMMRA", 4, 0, "SHA1", otpauth_ok, "3159", "" },

        { "hotp-0-26-6-SHA1", 0, "CU55SBHBOSBBV6QCBKXVLDMMRA", 6, 0, "SHA1", otpauth_ok, "514562", "" },
        { "hotp-1-26-6-SHA1", 1, "CU55SBHBOSBBV6QCBKXVLDMMRA", 6, 0, "SHA1", otpauth_ok, "841046", "" },
        { "hotp-42-26-6-SHA1", 42, "CU55SBHBOSBBV6QCBKXVLDMMRA", 6, 0, "SHA1", otpauth_ok, "911531", "" },
        { "hotp-7-26-6-SHA1", 2304820, "CU55SBHBOSBBV6QCBKXVLDMMRA", 6, 0, "SHA1", otpauth_ok, "750124", "" },
        { "hotp-10-26-6-SHA1", 1728577470, "CU55SBHBOSBBV6QCBKXVLDMMRA", 6, 0, "SHA1", otpauth_ok, "933159", "" },
        { "hotp-19-26-6-SHA1", 8354358971952073253, "CU55SBHBOSBBV6QCBKXVLDMMRA", 6, 0, "SHA1", otpauth_ok, "301848", "" },

        { "hotp-42-26-8-SHA1", 42, "CU55SBHBOSBBV6QCBKXVLDMMRA", 8, 0, "SHA1", otpauth_ok, "56911531", "" },
        { "hotp-7-26-8-SHA1", 2304820, "CU55SBHBOSBBV6QCBKXVLDMMRA", 8, 0, "SHA1", otpauth_ok, "56750124", "" },

        { "hotp-10-32-6-SHA1", 1728577470, "HCB4BZOKUM6I67CM2YKBQR6AISGPLEJT", 6, 0, "SHA1", otpauth_ok, "788730", "" },
        { "hotp-19-32-6-SHA1", 8354358971952073253, "HCB4BZOKUM6I67CM2YKBQR6AISGPLEJT", 6, 0, "SHA1", otpauth_ok, "776324", "" },

        { "hotp-7-52-4-SHA1", 2304820, "DEUK3DEMONVNXKMQNBYLGZS2PVSI2QA2RG73EANSQW4VJANNSJQA", 4, 0, "SHA1", otpauth_ok, "1005", "" },
        { "hotp-10-52-4-SHA1", 1728577470, "DEUK3DEMONVNXKMQNBYLGZS2PVSI2QA2RG73EANSQW4VJANNSJQA", 4, 0, "SHA1", otpauth_ok, "1358", "" },

        { NULL }
    };

static test_t TOTP_data[] =
    {
        { "totp-20-26-6-SHA1", 1728577470, "CU55SBHBOSBBV6QCBKXVLDMMRA", 6, 20, "SHA1", otpauth_ok, "", "284659" },
        { "totp-30-26-6-SHA1", 1728577470, "CU55SBHBOSBBV6QCBKXVLDMMRA", 6, 30, "SHA1", otpauth_ok, "", "756353" },
        { "totp-60-26-6-SHA1", 1728577470, "CU55SBHBOSBBV6QCBKXVLDMMRA", 6, 60, "SHA1", otpauth_ok, "", "321742" },
        { "totp-20-26-8-SHA1", 1728577470, "CU55SBHBOSBBV6QCBKXVLDMMRA", 8, 20, "SHA1", otpauth_ok, "", "27284659" },
        { "totp-30-26-8-SHA1", 1728577470, "CU55SBHBOSBBV6QCBKXVLDMMRA", 8, 30, "SHA1", otpauth_ok, "", "33756353" },
        { "totp-60-26-8-SHA1", 1728577470, "CU55SBHBOSBBV6QCBKXVLDMMRA", 8, 60, "SHA1", otpauth_ok, "", "46321742" },
        { "totp-20-32-6-SHA1", 1728577470, "HCB4BZOKUM6I67CM2YKBQR6AISGPLEJT", 6, 20, "SHA1", otpauth_ok, "", "317563" },
        { "totp-30-32-6-SHA1", 1728577470, "HCB4BZOKUM6I67CM2YKBQR6AISGPLEJT", 6, 30, "SHA1", otpauth_ok, "", "596087" },
        { "totp-60-32-6-SHA1", 1728577470, "HCB4BZOKUM6I67CM2YKBQR6AISGPLEJT", 6, 60, "SHA1", otpauth_ok, "", "663151" },
        { NULL }
    };

static bool
check_code(otpauth_ret_t gotret, otpauth_ret_t expret,
           const char *gotcode, const char *expcode)
{
    if (gotret != expret)
    {
        printf("### Expected %s, got %s\n",
                map_ret_code(expret), map_ret_code(gotret));
        return false;
    }
    if (gotcode != NULL && expcode != NULL)
    {
        if (gotret == otpauth_ok && strcmp(gotcode, expcode) != 0)
        {
            printf("### Expected %s, got %s\n", expcode, gotcode);
            return false;
        }
    }
    printf("Ok\n");
    return true;
}

static bool
check_pointer(void *ptr, bool expnull)
{
    if (expnull &&  ptr != NULL)
    {
        printf("### Expected NULL, got pointer\n");
        return false;
    }
    if (!expnull && ptr == NULL)
    {
        printf("### Expected pointer, got NULL\n");
        return false;
    }
    printf("Ok\n");
    return true;
}

static bool
check_string(const char *val, const char *exp)
{
    if (val == NULL)
    {
        printf("### Expected pointer, got NULL\n");
        return false;
    }
    if (strcmp(val, exp) != 0)
    {
        printf("### Expected %s, got %s\n", exp, val);
        return false;
    }
    printf("Ok\n");
    return true;
}

int
main(int argc, char **argv)
{
    otpauth_ret_t ret;
    bool test = true;
    char code[16];

    for (int i = 0 ; HOTP_data[i].name != NULL ; i++)
    {
        test_t *td = HOTP_data+i;

        printf("--- Test %s: ", td->name);
        ret = otpauth_hotp(td->counter,
                           td->secret,
                           td->digits,
                           td->algorithm,
                           code);
        test &= check_code(ret, td->ret, code, td->hotp);
    }

    for (int i = 0 ; TOTP_data[i].name != NULL ; i++)
    {
        test_t *td = TOTP_data+i;

        printf("--- Test %s: ", td->name);
        ret = otpauth_totp_at(td->counter,
                              td->secret,
                              td->period,
                              td->digits,
                              td->algorithm,
                              code, NULL);
        test &= check_code(ret, td->ret, code, td->totp);
    }

    char *secret;
    printf("--- Test secret bytes too small: ");
    secret = otpauth_secret(OTPAUTH_SECRET_MIN_BYTES-1);
    test &= check_pointer(secret, true);
    free(secret);

    char *uri;
    printf("--- Test bad type URI: ");
    uri = otpauth_uri("The Issuer", "The Label", NULL,
                      "xyz", "TQ5IMIXY3HNJCHP3CGBTKU4UUX7JLDIK",
                      0, 0, 0, NULL);
    test &= check_pointer(uri, true);
    printf("--- Test default HOTP URI: ");
    uri = otpauth_uri("The Issuer", "The Label", NULL,
                      "hotp", "TQ5IMIXY3HNJCHP3CGBTKU4UUX7JLDIK",
                      0, 0, 0, NULL);
    test &= check_string(uri,
                         "otpauth://hotp/The%20Issuer%3AThe%20Label?secret=TQ5IMIXY3HNJCHP3CGBTKU4UUX7JLDIK&issuer=The%20Issuer&counter=0");
    free(uri);
    printf("--- Test custom HOTP URI: ");
    uri = otpauth_uri("X:Y", "(pst)", NULL, "hotp",
                      "TQ5IMIXY3HNJCHP3CGBTKU4UUX7JLDIK",
                      42, 0, 8, "SHA256");
    test &= check_string(uri,
                         "otpauth://hotp/X%3AY%3A%28pst%29?secret=TQ5IMIXY3HNJCHP3CGBTKU4UUX7JLDIK&issuer=X%3AY&counter=42&digits=8&algorithm=SHA256");
    free(uri);

    printf("--- Test default TOTP URI: ");
    uri = otpauth_uri("Issuer&Son", "Label&Co", "http://some.where/pic.png",
                      "totp", "TQ5IMIXY3HNJCHP3CGBTKU4UUX7JLDIK",
                      0, 0, 0, NULL);
    test &= check_string(uri,
                         "otpauth://totp/Issuer%26Son%3ALabel%26Co?secret=TQ5IMIXY3HNJCHP3CGBTKU4UUX7JLDIK&issuer=Issuer%26Son&image=http%3A%2F%2Fsome.where%2Fpic.png");
    free(uri);
    printf("--- Test custom TOTP URI: ");
    uri = otpauth_uri("Issuer&Son", "Label&Co", "https://x.y.com/avatar.jpg",
                      "totp", "TQ5IMIXY3HNJCHP3CGBTKU4UUX7JLDIK",
                      0, 40, 4, "SHA512");
    test &= check_string(uri,
                         "otpauth://totp/Issuer%26Son%3ALabel%26Co?secret=TQ5IMIXY3HNJCHP3CGBTKU4UUX7JLDIK&issuer=Issuer%26Son&period=40&digits=4&algorithm=SHA512&image=https%3A%2F%2Fx.y.com%2Favatar.jpg");
    free(uri);

    if (test)
    {
        printf("\nTests passed\n");
        exit(0);
    }
    fprintf(stderr, "\n### Tests failed\n");
    exit(1);
}
