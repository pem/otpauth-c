/*
** pem 2024-10-07
**
** Functions for Time-based One-Time Passwords (TOTP, RFC 6238) and
** HMAC-based One-Time Passwords (HOTP, RFC 4226).
**
*/

#pragma once

#include <stdint.h>

typedef enum
    {
        otpauth_ok,
        otpauth_eb32,           /* Bad Base32 encoding of secret */
        otpauth_ekey,           /* Secret is shorter than 16 bytes */
        otpauth_ehmac,          /* HMAC computation failed */
        otpauth_epar,		/* Bad parameter (e.g. out of range) */
    } otpauth_ret_t;

#define OTPAUTH_DEFAULT_DIGITS 6
#define OTPAUTH_DEFAULT_ALGORITHM "SHA1"
#define OTPAUTH_DEFAULT_PERIOD 30
#define OTPAUTH_SECRET_MIN_BYTES 16

/* Calculate the HOTP code of 'counter' with 'digits' digits. (In the
   range 4-10.
   'b32secret' is a Base32 encoded secret, which must be at least 16
   bytes (before encoding).
   'algorithm' is the HMAC hash algorithm to use, a string in the
   format accepted by OpenSSL. Algorithms other than "SHA1", like
   "SHA256" and "SHA512" may not be supported by all mobile apps.
   The code is written to 'digbuf' which must have a size of at
   least 'digits'+1. */
otpauth_ret_t
otpauth_hotp(uint64_t counter,
             const char *b32secret,
             uint8_t digits,
             const char *algorithm,
             char *digbuf);

/* Calculate the TOTP code at time 't', which is Unix-time, seconds
   since 1970-01-01. 'period' is the time each code is valid, in
   seconds. (In the range 10-120.)
   The remaining time in seconds of the current period is written
   to 'timep' if it's not a NULL pointer. */
otpauth_ret_t
otpauth_totp_at(uint64_t t,
                const char *b32secret,
                uint8_t period,
                uint8_t digits,
                const char *algorithm,
                char *digbuf, uint64_t *timep);

/* Calculate the TOTP code at time now. */
otpauth_ret_t
otpauth_totp(const char *b32secret,
             uint8_t period,
             uint8_t digits,
             const char *algorithm,
             char *digbuf, uint64_t *timep);

/* Generate a secret of length 'bytes'. Returns a Base32 encoded
   string, allocated with malloc(). Note that 'bytes' is the binary
   size, the resulting string is longer.
   Returns NULL if 'bytes' is too small, or if allocation failed. */
char *
otpauth_secret(uint8_t bytes);

/* Returns an otpauth URI to 'uri', allocated with malloc().
   'type' is one of 'totp' or 'hotp'.
   'issuer' and 'label' must be non-empty strings; these are used to name
   the account when registering it in the App. Remember that they will be
   displayed on a small mobile device, so keep them short.
   'imageurl' is an URL to a small icon image that the App can use
   for the account entry.
   'counter' is the start counter for 'hotp', 'period' is the change
   period for 'totp' in seconds.
   If values are 0 (or NULL), or equal to the default values, they are
   omitted from the URI, in which case the App will use the defaults.
   Returns otpauth_epar for bad parameter or if allocation failed. */
char *
otpauth_uri(const char *issuer, const char *label, const char *imageurl,
            const char *type,
            const char *b32secret,
            uint64_t counter,
            uint8_t period,
            uint8_t digits,
	    const char *algorithm);


/* This rounds up to enough space for the base32 encoded string, including
   a final \0. The exact value is ceil((B)*8.0/5), but that requires a
   run-time math operation. */
#define BASE32_ENCODED_MIN_SIZE(B) ((((B)+1) * 8) / 5 + 1)

/* Encode a buffer 'bin' of length 'len' bytes to Base32 into the buffer
   'b32' (max. size 'b32max'). The string is terminated by a '\0'.
   Returns the length of the encoded string. If the buffer is too small
   the result is silently truncated and the returned value is 'b32max'.
   The resulting string is not padded at the end with '=', as this is
   redundant. */
size_t base32encode(const uint8_t *bin, size_t len, char *b32, size_t b32max);

/* Decode a Base32 encoded string 'b32' (\0 terminated) into the buffer
   'bin' (max. size 'binmax'). Returns the number of decoded bytes, or 0
   if the input string is not a correct Base32 string.  (RFC 4648 §6,
   upper case, no extra characters, in particular, no '=' padding at the
   end.) */
size_t base32decode(const char *b32, uint8_t *bin, size_t binmax);

/* The same as above, but returns a buffer allocated with malloc().
   If 'lenp' is not NULL, it's set to the resulting length. */
char *base32encode_alloc(const uint8_t *bin, size_t len);
uint8_t *base32decode_alloc(const char *b32, size_t *lenp);
