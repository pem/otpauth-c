/*
** pem 2024-10-06
**
** See otpauth.h
**
*/

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <inttypes.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/core_names.h>
#include <openssl/rand.h>

#include "otpauth.h"

#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define MAYBE_SWAP_ORDER(B) \
    do { \
        for (uint8_t *s = (B), *e = (B) + sizeof(B)-1 ;  s < e ; s++, e--) \
        { \
            uint8_t c = *s; \
            *s = *e; \
            *e = c; \
        } \
    } while(0)
#else
#define MAYBE_SWAP_ORDER(B)
#endif

otpauth_ret_t
otpauth_hotp(uint64_t counter,
             const char *b32secret,
             uint8_t digits,
             const char *algorithm,
             char *digbuf)
{
    otpauth_ret_t ret = otpauth_ok;
    union { uint64_t c; uint8_t b[sizeof(uint64_t)]; } u;

    u.c = counter;
    
    /* Big-endian is required */
    MAYBE_SWAP_ORDER(u.b);

    uint8_t hmac[EVP_MAX_MD_SIZE];
    size_t len = 0;

    EVP_MAC *mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    if (mac == NULL)
    {
        ret = otpauth_ehmac;
        goto err0;
    }

    EVP_MAC_CTX *mac_ctx = EVP_MAC_CTX_new(mac);
    if (mac_ctx == NULL)
    {
        ret = otpauth_ehmac;
        goto err1;
    }
    
    size_t seclen;
    uint8_t *secret = base32decode_alloc(b32secret, &seclen);
    if (secret == NULL)
    {
        ret = otpauth_eb32;
        goto err2;
    }
    if (seclen < 16)
    {
        ret = otpauth_ekey;
        goto err3;
    }

    OSSL_PARAM params[2];
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST,
                                                 (char *)algorithm,
                                                 strlen(algorithm)+1);
    params[1] = OSSL_PARAM_construct_end();
    if (! EVP_MAC_init(mac_ctx, secret, seclen, params) ||
        ! EVP_MAC_update(mac_ctx, u.b, sizeof(u.b)) ||
        ! EVP_MAC_final(mac_ctx, hmac, &len, sizeof(hmac)))
    {
        ret = otpauth_ehmac;
        goto err3;
    }

    uint8_t i = hmac[len-1] & 0xF;
    uint64_t trunc =
        ((hmac[i] & 0x7F) << 24) |
        (hmac[i+1] << 16) |
        (hmac[i+2] << 8) |
        hmac[i+3];
    /* digits is a tiny number, not worth depending on libm pow(). */
    uint64_t d = 1;
    for (uint_fast8_t i = 0 ; i < digits ; i++)
        d *= 10;
    snprintf(digbuf, digits+1, "%0*" PRIu64, (int)digits, trunc % d);

 err3:
    free(secret);
 err2:
    EVP_MAC_CTX_free(mac_ctx);
 err1:
    EVP_MAC_free(mac);
 err0:
    return ret;
}

otpauth_ret_t
otpauth_totp_at(uint64_t t,
                const char *b32secret,
                uint8_t period,
                uint8_t digits,
                const char *algorithm,
                char *digbuf, uint64_t *timep)
{
    uint64_t c = t / period;
    uint64_t r = period - t % period;

    otpauth_ret_t ret = otpauth_hotp(c, b32secret, digits, algorithm, digbuf);
    if (timep != NULL)
        *timep = r;
    return ret;
}

otpauth_ret_t
otpauth_totp(const char *b32secret,
             uint8_t period,
             uint8_t digits,
             const char *algorithm,
             char *digbuf, uint64_t *timep)
{
    uint64_t t = time(NULL);

    return otpauth_totp_at(t, b32secret, period, digits, algorithm,
                           digbuf, timep);
}

char *
otpauth_secret(uint8_t bytes)
{
    uint8_t *rnd;
    char *s = NULL;

    if (bytes < OTPAUTH_SECRET_MIN_BYTES)
        return NULL;

    if ((rnd = malloc(bytes)) != NULL)
    {
        RAND_bytes(rnd, bytes);

        s = base32encode_alloc(rnd, bytes);
        free(rnd);
    }

    return s;
}
