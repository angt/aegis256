#pragma once

#include <stddef.h>

#define AEGIS256_NPUBBYTES 32

int
aegis256_is_available(void);

int
aegis256_encrypt(unsigned char *,
           const unsigned char *, size_t,
           const unsigned char *, size_t,
           const unsigned char *,
           const unsigned char *,
                 unsigned char *);

int
aegis256_decrypt(unsigned char *,
           const unsigned char *, size_t,
           const unsigned char *, size_t,
           const unsigned char *,
           const unsigned char *,
           const unsigned char *, size_t);
