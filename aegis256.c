// Adapted from https://bench.cr.yp.to/supercop/supercop-20190816.tar.xz

#include "errno.h"
#include "aegis256.h"
#include <string.h>

#ifndef __has_include
#define __has_include(X) 0
#endif

#if defined(__x86_64__) && (__has_include("x86intrin.h") && __has_include("cpuid.h"))

#include <cpuid.h>

int
aegis256_is_available(void)
{
    unsigned eax, ebx, ecx, edx;
    __cpuid(1, eax, ebx, ecx, edx);
    return (ecx & bit_AES) && (edx & bit_SSE2);
}

#ifdef __clang__
#pragma clang attribute push (__attribute__((target("sse2,aes"))),apply_to=function)
#else
#pragma GCC target("sse2,aes")
#endif

#include <x86intrin.h>

typedef __m128i       x128;
#define aesenc(X,Y)   _mm_aesenc_si128((X), (Y))
#define xor128(X,Y)   _mm_xor_si128((X), (Y))
#define and128(X,Y)   _mm_and_si128((X), (Y))
#define load128(X)    _mm_loadu_si128((const x128 *)(X))
#define store128(X,Y) _mm_storeu_si128((x128 *)(X), (Y))
#define set2x64(X,Y)  _mm_set_epi64x((X), (Y))
#define set16x8(...)  _mm_set_epi8(__VA_ARGS__)

#elif defined(__linux__) && (defined(__ARM_NEON_FP) || defined(__aarch64__))

#ifdef __clang__
// XXX: not tested...
#pragma clang attribute push (__attribute__((target("+crypto"))),apply_to=function)
#else
#pragma GCC target("+crypto")
#endif

#ifdef __ARM_FEATURE_CRYPTO
#include <sys/auxv.h>
#include <arm_neon.h>

typedef uint8x16_t    x128;
#define aesenc(X,Y)   veorq_u8(vaesmcq_u8(vaeseq_u8((X), (x128){})), (Y))
#define xor128(X,Y)   veorq_u8((X), (Y))
#define and128(X,Y)   vandq_u8((X), (Y))
#define load128(X)    vld1q_u8((const uint8_t *)(X))
#define store128(X,Y) vst1q_u8((uint8_t *)(X), (Y))

static inline x128
set2x64(uint64_t x2, uint64_t x1)
{
    uint64_t __attribute__((aligned(16)))
    data[] = {x1, x2};
    return vreinterpretq_u8_u64(vld1q_u64(data));
}

static inline x128
set16x8(uint8_t xf, uint8_t xe, uint8_t xd, uint8_t xc,
        uint8_t xb, uint8_t xa, uint8_t x9, uint8_t x8,
        uint8_t x7, uint8_t x6, uint8_t x5, uint8_t x4,
        uint8_t x3, uint8_t x2, uint8_t x1, uint8_t x0)
{
    uint8_t __attribute__((aligned(16)))
    data[] = {x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, xa, xb, xc, xd, xe, xf};
    return vld1q_u8(data);
}

int
aegis256_is_available(void)
{
    return (getauxval(AT_HWCAP) & HWCAP_AES)
#ifdef HWCAP2_AES
        || (getauxval(AT_HWCAP2) & HWCAP2_AES)
#endif
        ;
}

#endif // __ARM_FEATURE_CRYPTO
#endif

#ifdef aesenc

static inline void
aegis256_update(x128 *const restrict state,
                const x128 data)
{
    x128 tmp = aesenc(state[5], state[0]);
    state[5] = aesenc(state[4], state[5]);
    state[4] = aesenc(state[3], state[4]);
    state[3] = aesenc(state[2], state[3]);
    state[2] = aesenc(state[1], state[2]);
    state[1] = aesenc(state[0], state[1]);
    state[0] = xor128(tmp, data);
}

static inline void
aegis256_enc(unsigned char *const restrict dst,
             const unsigned char *const restrict src,
             x128 *const restrict state)
{
    x128 tmp, msg = load128(src);
    tmp = xor128(msg, state[5]);
    tmp = xor128(tmp, state[4]);
    tmp = xor128(tmp, state[1]);
    tmp = xor128(tmp, and128(state[2], state[3]));
    store128(dst, tmp);

    aegis256_update(state, msg);
}

static inline void
aegis256_dec(unsigned char *const restrict dst,
             const unsigned char *const restrict src,
             x128 *const restrict state)
{
    x128 tmp = load128(src);
    tmp = xor128(tmp, state[5]);
    tmp = xor128(tmp, state[4]);
    tmp = xor128(tmp, state[1]);
    tmp = xor128(tmp, and128(state[2], state[3]));
    store128(dst, tmp);

    aegis256_update(state, tmp);
}

static void
aegis256_init(const unsigned char *const key,
              const unsigned char *const iv,
              x128 *const restrict state)
{
    x128 k1 = load128(&key[0]);
    x128 k2 = load128(&key[16]);
    x128 k3 = xor128(k1, load128(&iv[0]));
    x128 k4 = xor128(k2, load128(&iv[16]));

    state[0] = k3;
    state[1] = k4;
    state[2] = set16x8(0xdd, 0x28, 0xb5, 0x73, 0x42, 0x31, 0x11, 0x20,
                       0xf1, 0x2f, 0xc2, 0x6d, 0x55, 0x18, 0x3d, 0xdb);
    state[3] = set16x8(0x62, 0x79, 0xe9, 0x90, 0x59, 0x37, 0x22, 0x15,
                       0x0d, 0x08, 0x05, 0x03, 0x02, 0x01, 0x01, 0x00);
    state[4] = xor128(k1, state[3]);
    state[5] = xor128(k2, state[2]);

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
             x128 *const restrict state)
{
    x128 tmp = set2x64(mlen << 3, adlen << 3);
    tmp = xor128(tmp, state[3]);

    for (int i = 0; i < 7; i++)
        aegis256_update(state, tmp);

    tmp = xor128(state[5], state[4]);
    tmp = xor128(tmp, state[3]);
    tmp = xor128(tmp, state[2]);
    tmp = xor128(tmp, state[1]);
    tmp = xor128(tmp, state[0]);

    store128(mac, tmp);
}

int
aegis256_encrypt(unsigned char *c, unsigned long long *len,
                 const unsigned char *m, unsigned long long mlen,
                 const unsigned char *ad, unsigned long long adlen,
                 const unsigned char *npub,
                 const unsigned char *k)
{
    x128 state[6];
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
    x128 state[6];
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
        state[0] = xor128(state[0], load128(dst));
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

#else // aesenc

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

#endif // aesenc
