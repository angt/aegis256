// Adapted from https://bench.cr.yp.to/supercop/supercop-20190816.tar.xz

#include "aegis256.h"

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include <errno.h>
#include <setjmp.h>
#include <signal.h>
#include <string.h>

#ifndef __has_include
#define __has_include(X) 0
#endif

#if defined(__x86_64__) && __has_include("x86intrin.h")
#include <x86intrin.h>

typedef __m128i       x128;
#define aesenc(X,Y)   _mm_aesenc_si128((X), (Y))
#define xor128(X,Y)   _mm_xor_si128((X), (Y))
#define and128(X,Y)   _mm_and_si128((X), (Y))
#define load128(X)    _mm_loadu_si128((const x128 *)(X))
#define store128(X,Y) _mm_storeu_si128((x128 *)(X), (Y))
#define set2x64(X,Y)  _mm_set_epi64x((long long)(X), (long long)(Y))
#define target_aes    __attribute__((target("aes,sse2")))

#elif defined(__aarch64__) && __has_include("arm_neon.h")
#include <arm_neon.h>

typedef uint8x16_t    x128;
#define aesenc(X,Y)   veorq_u8(vaesmcq_u8(vaeseq_u8((X), (x128){})), (Y))
#define xor128(X,Y)   veorq_u8((X), (Y))
#define and128(X,Y)   vandq_u8((X), (Y))
#define load128(X)    vld1q_u8((const uint8_t *)(X))
#define store128(X,Y) vst1q_u8((uint8_t *)(X), (Y))
#define set2x64(X,Y)  vreinterpretq_u8_u64(vsetq_lane_u64((X), vmovq_n_u64((Y)), 1))
#define target_aes    __attribute__((target("+aes")))

#endif

#ifdef aesenc

target_aes static inline void
aegis256_update(x128 *const state, x128 data)
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
aegis256_enc(unsigned char *const dst,
       const unsigned char *const src,
             x128 *const state)
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
aegis256_dec(unsigned char *const dst,
       const unsigned char *const src,
             x128 *const state)
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
              x128 *const state)
{
    __attribute__((aligned(16)))
    static const unsigned char c[] = {
        0xdb, 0x3d, 0x18, 0x55, 0x6d, 0xc2, 0x2f, 0xf1,
        0x20, 0x11, 0x31, 0x42, 0x73, 0xb5, 0x28, 0xdd,
        0x00, 0x01, 0x01, 0x02, 0x03, 0x05, 0x08, 0x0d,
        0x15, 0x22, 0x37, 0x59, 0x90, 0xe9, 0x79, 0x62,
    };
    x128 k1 = load128(&key[0]);
    x128 k2 = load128(&key[16]);
    x128 k3 = xor128(k1, load128(&iv[0]));
    x128 k4 = xor128(k2, load128(&iv[16]));

    state[0] = k3;
    state[1] = k4;
    state[2] = load128(&c[0]);
    state[3] = load128(&c[16]);
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
aegis256_tag(unsigned char *const mac,
             size_t mlen, size_t adlen,
             x128 *const state)
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
aegis256_encrypt(unsigned char *c,
           const unsigned char *m,  size_t mlen,
           const unsigned char *ad, size_t adlen,
           const unsigned char *npub,
           const unsigned char *k,
                 unsigned char *tag)
{
    x128 state[6];
    unsigned char src[16];
    unsigned char dst[16];
    size_t i;

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
    aegis256_tag(tag, mlen, adlen, state);

    return 0;
}

int
aegis256_decrypt(unsigned char *m,
           const unsigned char *c,   size_t clen,
           const unsigned char *ad,  size_t adlen,
           const unsigned char *npub,
           const unsigned char *k,
           const unsigned char *tag, size_t taglen)
{
    x128 state[6];
    unsigned char src[16];
    unsigned char dst[16];
    unsigned char tmp[16];
    size_t i;
    unsigned int ret = 0;

    aegis256_init(k, npub, state);

    for (i = 0; i + 16 <= adlen; i += 16)
        aegis256_enc(dst, ad + i, state);

    if (adlen & 0xf) {
        memset(src, 0, 16);
        memcpy(src, ad + i, adlen & 0xf);
        aegis256_enc(dst, src, state);
    }

    for (i = 0; i + 16 <= clen; i += 16)
        aegis256_dec(m + i, c + i, state);

    if (clen & 0xf) {
        memset(src, 0, 16);
        memcpy(src, c + i, clen & 0xf);
        aegis256_dec(dst, src, state);
        memcpy(m + i, dst, clen & 0xf);

        memset(dst, 0, clen & 0xf);
        state[0] = xor128(state[0], load128(dst));
    }
    aegis256_tag(tmp, clen, adlen, state);

    if (taglen > 16)
        taglen = 16;

    for (i = 0; i < taglen; i++)
        ret |= (tmp[i] ^ tag[i]);

    return 1 - (1 & ((ret - 1) >> 8));
}

static sigjmp_buf sigill_jmp;

static void
sigill_handler(int sig) {
    (void)sig;
    siglongjmp(sigill_jmp, 1);
}

int
aegis256_is_available(void)
{
    static int init = 0;
    static int available = 0;

    if (init)
        return available;

    struct sigaction sa_old, sa = {
        .sa_handler = sigill_handler
    };
    sigemptyset(&sa.sa_mask);

    if (sigaction(SIGILL, &sa, &sa_old))
        return 0;

    init = 1;

    if (sigsetjmp(sigill_jmp, 1) == 0) {
        unsigned char m[] = "MUD";
        unsigned char c[sizeof(m)];
        unsigned char npub[AEGIS256_NPUBBYTES] = {1};
        unsigned char key[32] = {42};
        unsigned char tag[16];
        aegis256_encrypt(c, m, sizeof(m), NULL, 0, npub, key, tag);
        available = !aegis256_decrypt(m, c, sizeof(c), NULL, 0, npub, key, tag, 16);
    }
    sigaction(SIGILL, &sa_old, 0);

    return available;
}

#else // aesenc

int
aegis256_is_available(void)
{
    return 0;
}

int
aegis256_encrypt(unsigned char *c,
           const unsigned char *m,  size_t mlen,
           const unsigned char *ad, size_t adlen,
           const unsigned char *npub,
           const unsigned char *k,
                 unsigned char *tag)
{
    errno = ENOSYS;
    return -1;
}

int
aegis256_decrypt(unsigned char *m,
           const unsigned char *c,   size_t clen,
           const unsigned char *ad,  size_t adlen,
           const unsigned char *npub,
           const unsigned char *k,
           const unsigned char *tag, size_t taglen)
{
    errno = ENOSYS;
    return -1;
}

#endif // aesenc
