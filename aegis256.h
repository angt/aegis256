#pragma once

int
aegis256_encrypt(unsigned char *, unsigned long long *,
                 const unsigned char *, unsigned long long,
                 const unsigned char *, unsigned long long,
                 const unsigned char *,
                 const unsigned char *);

int
aegis256_decrypt(unsigned char *, unsigned long long *,
                 const unsigned char *, unsigned long long,
                 const unsigned char *, unsigned long long,
                 const unsigned char *,
                 const unsigned char *);
