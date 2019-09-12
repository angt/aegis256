// Adapted from https://bench.cr.yp.to/supercop/supercop-20190816.tar.xz

#include "errno.h"
#include "aegis256.h"

#if __has_include("x86intrin.h")

#include <string.h>
#include <x86intrin.h>
#include <cpuid.h>

#ifdef __clang__
#pragma clang attribute push (__attribute__((target("sse2,aes"))),apply_to=function)
#else
#pragma GCC target("sse2,aes")
#endif

static inline void
aegis256_update(__m128i *const restrict state,
                const __m128i data)
{
    __m128i z = _mm_aesenc_si128(state[5], state[0]);
    state[5]  = _mm_aesenc_si128(state[4], state[5]);
    state[4]  = _mm_aesenc_si128(state[3], state[4]);
    state[3]  = _mm_aesenc_si128(state[2], state[3]);
    state[2]  = _mm_aesenc_si128(state[1], state[2]);
    state[1]  = _mm_aesenc_si128(state[0], state[1]);
    state[0]  = _mm_xor_si128(z, data);
}

static inline void
aegis256_enc(unsigned char *const restrict dst,
             const unsigned char *const restrict src,
             __m128i *const restrict state)
{
    __m128i tmp, msg = _mm_loadu_si128((const __m128i *)src);
    tmp = _mm_xor_si128(msg, state[5]);
    tmp = _mm_xor_si128(tmp, state[4]);
    tmp = _mm_xor_si128(tmp, state[1]);
    tmp = _mm_xor_si128(tmp, _mm_and_si128(state[2], state[3]));
    _mm_storeu_si128((__m128i *)dst, tmp);

    aegis256_update(state, msg);
}

static inline void
aegis256_dec(unsigned char *const restrict dst,
             const unsigned char *const restrict src,
             __m128i *const restrict state)
{
    __m128i tmp = _mm_loadu_si128((const __m128i *)src);
    tmp = _mm_xor_si128(tmp, state[5]);
    tmp = _mm_xor_si128(tmp, state[4]);
    tmp = _mm_xor_si128(tmp, state[1]);
    tmp = _mm_xor_si128(tmp, _mm_and_si128(state[2], state[3]));
    _mm_storeu_si128((__m128i *)dst, tmp);

    aegis256_update(state, tmp);
}

static void
aegis256_init(const unsigned char *const key,
              const unsigned char *const iv,
              __m128i *const restrict state)
{
    __m128i k1 = _mm_loadu_si128((const __m128i *)&key[0]);
    __m128i k2 = _mm_loadu_si128((const __m128i *)&key[16]);
    __m128i k3 = _mm_xor_si128(k1, _mm_loadu_si128((const __m128i *)&iv[0]));
    __m128i k4 = _mm_xor_si128(k2, _mm_loadu_si128((const __m128i *)&iv[16]));

    state[0] = k3;
    state[1] = k4;
    state[2] = _mm_set_epi8(0xdd, 0x28, 0xb5, 0x73, 0x42, 0x31, 0x11, 0x20,
                            0xf1, 0x2f, 0xc2, 0x6d, 0x55, 0x18, 0x3d, 0xdb);
    state[3] = _mm_set_epi8(0x62, 0x79, 0xe9, 0x90, 0x59, 0x37, 0x22, 0x15,
                            0x0d, 0x08, 0x05, 0x03, 0x02, 0x01, 0x01, 0x00);
    state[4] = _mm_xor_si128(k1, state[3]);
    state[5] = _mm_xor_si128(k2, state[2]);

    for (int i = 0; i < 4; i++) {
        aegis256_update(state, k1);
        aegis256_update(state, k2);
        aegis256_update(state, k3);
        aegis256_update(state, k4);
    }
}

static void
aegis256_tag(unsigned char *const restrict mac,
             const unsigned long long mlen,
             const unsigned long long adlen,
             __m128i *const restrict state)
{
    __m128i tmp = _mm_set_epi64x(mlen << 3, adlen << 3);
    tmp = _mm_xor_si128(tmp, state[3]);

    for (int i = 0; i < 7; i++)
        aegis256_update(state, tmp);

    tmp = _mm_xor_si128(state[5], state[4]);
    tmp = _mm_xor_si128(tmp, state[3]);
    tmp = _mm_xor_si128(tmp, state[2]);
    tmp = _mm_xor_si128(tmp, state[1]);
    tmp = _mm_xor_si128(tmp, state[0]);

    _mm_storeu_si128((__m128i *)mac, tmp);
}

int
aegis256_is_available(void)
{
    unsigned eax, ebx, ecx, edx;
    __cpuid(1, eax, ebx, ecx, edx);
    return (ecx & bit_AES) && (edx & bit_SSE2);
}

int
aegis256_encrypt(unsigned char *c, unsigned long long *len,
                 const unsigned char *m, unsigned long long mlen,
                 const unsigned char *ad, unsigned long long adlen,
                 const unsigned char *npub,
                 const unsigned char *k)
{
    __m128i state[6];
    unsigned char src[16];
    unsigned char dst[16];
    unsigned long long i;

    aegis256_init(k, npub, state);

    for (i = 0; i + 16 <= adlen; i += 16)
        aegis256_enc(dst, ad + i, state);

    if (adlen & 0xf) {
        memset(src, 0, 16);
        memcpy(src, ad + i, adlen & 0xf);
        aegis256_enc(dst, src, state);
    }

    for (i = 0; i + 16 <= mlen; i += 16)
        aegis256_enc(c + i, m + i, state);

    if (mlen & 0xf) {
        memset(src, 0, 16);
        memcpy(src, m + i, mlen & 0xf);
        aegis256_enc(dst, src, state);
        memcpy(c + i, dst, mlen & 0xf);
    }

    aegis256_tag(c + mlen, mlen, adlen, state);

    if (len)
        *len = mlen + 16;

    return 0;
}

int
aegis256_decrypt(unsigned char *m, unsigned long long *len,
                 const unsigned char *c, unsigned long long clen,
                 const unsigned char *ad, unsigned long long adlen,
                 const unsigned char *npub,
                 const unsigned char *k)
{
    __m128i state[6];
    unsigned char src[16];
    unsigned char dst[16];
    unsigned char tag[16];
    unsigned long long i;
    unsigned int ret = 0;

    if (clen < 16) {
        errno = EINVAL;
        return -1;
    }

    unsigned long long mlen = clen - 16;

    if (len)
        *len = mlen;

    aegis256_init(k, npub, state);

    for (i = 0; i + 16 <= adlen; i += 16)
        aegis256_enc(dst, ad + i, state);

    if (adlen & 0xf) {
        memset(src, 0, 16);
        memcpy(src, ad + i, adlen & 0xf);
        aegis256_enc(dst, src, state);
    }

    for (i = 0; i + 16 <= mlen; i += 16)
        aegis256_dec(m + i, c + i, state);

    if (mlen & 0xf) {
        memset(src, 0, 16);
        memcpy(src, c + i, mlen & 0xf);
        aegis256_dec(dst, src, state);
        memcpy(m + i, dst, mlen & 0xf);

        memset(dst, 0, mlen & 0xf);
        state[0] = _mm_xor_si128(state[0], _mm_loadu_si128((__m128i *)dst));
    }

    aegis256_tag(tag, mlen, adlen, state);

    for (i = 0; i < 16; i++)
        ret |= (tag[i] ^ c[i + mlen]);

    return 1 - (1 & ((ret - 1) >> 8));
}

#ifdef __clang__
#pragma clang attribute pop
#else
#pragma GCC reset_options
#endif

#else

int
aegis256_is_available(void)
{
    return 0;
}

int
aegis256_encrypt(unsigned char *c, unsigned long long *len,
                 const unsigned char *m, unsigned long long mlen,
                 const unsigned char *ad, unsigned long long adlen,
                 const unsigned char *npub,
                 const unsigned char *k)
{
    errno = ENOSYS;
    return -1;
}

int
aegis256_decrypt(unsigned char *m, unsigned long long *len,
                 const unsigned char *c, unsigned long long clen,
                 const unsigned char *ad, unsigned long long adlen,
                 const unsigned char *npub,
                 const unsigned char *k)
{
    errno = ENOSYS;
    return -1;
}

#endif
