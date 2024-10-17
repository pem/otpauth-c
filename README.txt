A minimalist library for computing Time-based One-Time Passwords
(TOTP, RFC 6238), and HMAC-based One-Time Passwords (HOTP, RFC 4226);
second factor authentication methods.

- Requires OpenSSL 3.x.
- Uses stdint types, gcc -std=c11 recommended.
- Works on 32- and 64-bit platforms.
- Tested on different Linuxes (x86 and PPC), AIX, Solaris, and Mac OS X.
- Supports different number of digits, time periods (for TOTP), and
  HMAC hash algorithms.
- Function for generating an otpauth URI, for QR code.

NOTE: Many Second Factor Apps for mobile devices do NOT support non-default
settings. Some will accept other settings but silently ignore them and use
the defaults anyway. (Which of course will not work.)
When in doubt, use the default values: 6, 30, and "SHA1", for digits, period,
and algorithm respectively.
