/*
** pem 2024-10-14
**
** See otpauth.h
**
*/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <inttypes.h>

#include "otpauth.h"

static char *
otpauth_uri_grow(char *in, size_t *sizep)
{
    size_t size = *sizep + 16;
    char *out = realloc(in, size);

    if (out == NULL)
    {
        free(in);
        return NULL;
    }
    *sizep = size;
    return out;
}

/* Accepted chars:
   ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~" */
static char *
otpauth_uri_encode(const char *s)
{
    size_t i = 0, size = 16;
    char *out = malloc(size);

    if (out != NULL)
    {
        for (; *s != '\0' ; s++)
        {
            if (('A' <= *s && *s <= 'Z') ||
                ('a' <= *s && *s <= 'z') ||
                ('0' <= *s && *s <= '9') ||
                *s == '-' || *s == '.' || *s == '_' || *s == '~')
            {
                if (i == size-2 && /* *s and \0 */
                    (out = otpauth_uri_grow(out, &size)) == NULL)
                    return NULL;
                out[i++] = *s;
                continue;
            }
            if (i == size-4 &&  /* %XX and \0 */
                (out = otpauth_uri_grow(out, &size)) == NULL)
                return NULL;
            out[i++] = '%';
            snprintf(out+i, 3, "%02" PRIX8, (uint8_t)(*s));
            i += 2;
        }
        out[i] = '\0';
    }
    return out;
}

char *
otpauth_uri(const char *issuer, const char *label, const char *imageurl,
            const char *type,
            const char *b32secret,
            uint64_t counter,
            uint8_t period,
            uint8_t digits,
	    const char *algorithm)
{
    bool totp;
    char cnt[32], per[16], dig[16], alg[32];
    char *iss = NULL, *lab = NULL, *img = NULL, *uri = NULL;

    if (issuer == NULL || *issuer == '\0')
        return NULL;
    if (label == NULL || *label == '\0')
        return NULL;
    if (type == NULL)
        return NULL;
    if (strcmp(type, "totp") == 0)
        totp = true;
    else if (strcmp(type, "hotp") == 0)
        totp = false;
    else
        return NULL;

    iss = otpauth_uri_encode(issuer);
    if (iss == NULL)
        return NULL;
    lab = otpauth_uri_encode(label);
    if (lab == NULL)
        goto done;

    if (imageurl == NULL)
    {                           /* Empty string */
        img = malloc(1);
        if (img == NULL)
            goto done;
        img[0] = '\0';
    }
    else
    {
        char *url = otpauth_uri_encode(imageurl);
        if (url == NULL)
            goto done;
        size_t imglen = 8 + strlen(url); /* &image=...\0 */
        img = malloc(imglen);
        if (img == NULL)
        {
            free(url);
            goto done;
        }
        snprintf(img, imglen, "&image=%s", url);
        free(url);
    }

    if (totp)
        cnt[0] = '\0';
    else
        snprintf(cnt, sizeof(cnt), "&counter=%" PRIu64, counter);

    if (period == 0 || period == OTPAUTH_DEFAULT_PERIOD)
        per[0] = '\0';
    else
        snprintf(per, sizeof(per), "&period=%" PRIu8, period);

    if (digits == 0 || digits == OTPAUTH_DEFAULT_DIGITS)
        dig[0] = '\0';
    else
        snprintf(dig, sizeof(dig), "&digits=%" PRIu8, digits);

    if (algorithm == NULL || strcmp(algorithm, OTPAUTH_DEFAULT_ALGORITHM) == 0)
        alg[0] = '\0';
    else
        snprintf(alg, sizeof(alg), "&algorithm=%s", algorithm);

    /* The base URI is "otpauth://xxxx/%3A?secret=&issuer=", 34 characters,
       plus a final '\0'. We add a few extra just to be on the safe side. */
    size_t isslen = strlen(iss);
    size_t size = 40 + isslen + strlen(lab) + strlen(b32secret) + isslen +
        strlen(dig) + strlen(alg) + strlen(img);

    if (totp)
        size += strlen(per);
    else
        size += strlen(cnt);

    uri = malloc(size);

    /* Why issuer twice?
       Some apps doesn't pick up the first issuer, but does use &issuer=.
       (And some apps doesn't use either, but only picks up the label.) */
    if (totp)
        snprintf(uri, size,
                 "otpauth://totp/%s%%3A%s?secret=%s&issuer=%s%s%s%s%s",
                 iss, lab, b32secret, iss, per, dig, alg, img);
    else
        snprintf(uri, size,
                 "otpauth://hotp/%s%%3A%s?secret=%s&issuer=%s%s%s%s%s",
                 iss, lab, b32secret, iss, cnt, dig, alg, img);

 done:
    free(img);
    free(iss);
    free(lab);

    return uri;
}
