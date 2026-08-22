/*
 * Pollard Kangaroo (interval ECDLP) — secp256k1.
 * Ready when puzzle #71–#74 pubkey leaks. Affine jumps; status JSON.
 *
 * Build: gcc -O3 -march=native -o scripts/kangaroo scripts/kangaroo_c.c
 * Usage:
 *   ./scripts/kangaroo --bench
 *   ./scripts/kangaroo --toy
 *   ./scripts/kangaroo --pubkey HEX --lo HEX --hi HEX [--limit N]
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <stdbool.h>

typedef struct { uint64_t d[4]; } u256;

static const u256 SECP256K1_P = {
    { 0xFFFFFFFEFFFFFC2FULL, 0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL }
};
static const u256 SECP256K1_N = {
    { 0xBFD25E8CD0364141ULL, 0xBAAEDCE6AF48A03BULL, 0xFFFFFFFFFFFFFFFEULL, 0xFFFFFFFFFFFFFFFFULL }
};
static const u256 SECP256K1_GX = {
    { 0x59F2815B16F81798ULL, 0x029BFCDB2DCE28D9ULL, 0x55A06295CE870B07ULL, 0x79BE667EF9DCBBACULL }
};
static const u256 SECP256K1_GY = {
    { 0x9C47D08FFB10D4B8ULL, 0xFD17B448A6855419ULL, 0x5DA4FBFC0E1108A8ULL, 0x483ADA7726A3C465ULL }
};

typedef struct { u256 X; u256 Y; } PointAffine;

static inline void u256_add_mod(u256 *res, const u256 *a, const u256 *b) {
    __uint128_t c = 0;
    u256 t;
    c = (__uint128_t)a->d[0] + b->d[0]; t.d[0] = (uint64_t)c; c >>= 64;
    c += (__uint128_t)a->d[1] + b->d[1]; t.d[1] = (uint64_t)c; c >>= 64;
    c += (__uint128_t)a->d[2] + b->d[2]; t.d[2] = (uint64_t)c; c >>= 64;
    c += (__uint128_t)a->d[3] + b->d[3]; t.d[3] = (uint64_t)c; c >>= 64;
    if (c || (t.d[3] == 0xFFFFFFFFFFFFFFFFULL && t.d[2] == 0xFFFFFFFFFFFFFFFFULL &&
              t.d[1] == 0xFFFFFFFFFFFFFFFFULL && t.d[0] >= 0xFFFFFFFEFFFFFC2FULL)) {
        __int128_t borrow = 0;
        borrow = (__int128_t)t.d[0] - SECP256K1_P.d[0]; res->d[0] = (uint64_t)borrow; borrow >>= 64;
        borrow += (__int128_t)t.d[1] - SECP256K1_P.d[1]; res->d[1] = (uint64_t)borrow; borrow >>= 64;
        borrow += (__int128_t)t.d[2] - SECP256K1_P.d[2]; res->d[2] = (uint64_t)borrow; borrow >>= 64;
        borrow += (__int128_t)t.d[3] - SECP256K1_P.d[3]; res->d[3] = (uint64_t)borrow;
    } else {
        *res = t;
    }
}

static inline void u256_sub_mod(u256 *res, const u256 *a, const u256 *b) {
    __int128_t borrow = 0;
    u256 t;
    borrow = (__int128_t)a->d[0] - b->d[0]; t.d[0] = (uint64_t)borrow; borrow >>= 64;
    borrow += (__int128_t)a->d[1] - b->d[1]; t.d[1] = (uint64_t)borrow; borrow >>= 64;
    borrow += (__int128_t)a->d[2] - b->d[2]; t.d[2] = (uint64_t)borrow; borrow >>= 64;
    borrow += (__int128_t)a->d[3] - b->d[3]; t.d[3] = (uint64_t)borrow; borrow >>= 64;
    if (borrow != 0) {
        __uint128_t c = 0;
        c = (__uint128_t)t.d[0] + SECP256K1_P.d[0]; res->d[0] = (uint64_t)c; c >>= 64;
        c += (__uint128_t)t.d[1] + SECP256K1_P.d[1]; res->d[1] = (uint64_t)c; c >>= 64;
        c += (__uint128_t)t.d[2] + SECP256K1_P.d[2]; res->d[2] = (uint64_t)c; c >>= 64;
        c += (__uint128_t)t.d[3] + SECP256K1_P.d[3]; res->d[3] = (uint64_t)c;
    } else {
        *res = t;
    }
}

static inline void u256_mul_mod(u256 *res, const u256 *a, const u256 *b) {
    uint64_t r[8] = {0};
    for (int i = 0; i < 4; i++) {
        __uint128_t c = 0;
        uint64_t ai = a->d[i];
        for (int j = 0; j < 4; j++) {
            c += (__uint128_t)ai * b->d[j] + r[i + j];
            r[i + j] = (uint64_t)c;
            c >>= 64;
        }
        r[i + 4] += (uint64_t)c;
    }
    const uint64_t C = 0x1000003D1ULL;
    __uint128_t acc = 0;
    uint64_t s[5] = {0};
    for (int i = 0; i < 4; i++) {
        acc += r[i];
        s[i] = (uint64_t)acc;
        acc >>= 64;
    }
    s[4] = (uint64_t)acc;
    for (int i = 0; i < 4; i++) {
        __uint128_t prod = (__uint128_t)r[4 + i] * C;
        __uint128_t c = 0;
        for (int j = 0; j + i < 5; j++) {
            c += (__uint128_t)s[i + j] + (uint64_t)prod;
            s[i + j] = (uint64_t)c;
            c >>= 64;
            prod >>= 64;
        }
    }
    acc = s[4] * C;
    for (int i = 0; i < 4; i++) {
        acc += s[i];
        res->d[i] = (uint64_t)acc;
        acc >>= 64;
    }
    if (acc || (res->d[3] == 0xFFFFFFFFFFFFFFFFULL && res->d[2] == 0xFFFFFFFFFFFFFFFFULL &&
                res->d[1] == 0xFFFFFFFFFFFFFFFFULL && res->d[0] >= 0xFFFFFFFEFFFFFC2FULL)) {
        __int128_t borrow = 0;
        borrow = (__int128_t)res->d[0] - SECP256K1_P.d[0]; res->d[0] = (uint64_t)borrow; borrow >>= 64;
        borrow += (__int128_t)res->d[1] - SECP256K1_P.d[1]; res->d[1] = (uint64_t)borrow; borrow >>= 64;
        borrow += (__int128_t)res->d[2] - SECP256K1_P.d[2]; res->d[2] = (uint64_t)borrow; borrow >>= 64;
        borrow += (__int128_t)res->d[3] - SECP256K1_P.d[3]; res->d[3] = (uint64_t)borrow;
    }
}

static void u256_inv_mod(u256 *res, const u256 *a) {
    u256 cur = *a;
    u256 out = { { 1, 0, 0, 0 } };
    u256 exp = { { 0xFFFFFFFEFFFFFC2DULL, 0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL } };
    for (int word = 0; word < 4; word++) {
        uint64_t w = exp.d[word];
        for (int b = 0; b < 64; b++) {
            if (w & 1) u256_mul_mod(&out, &out, &cur);
            u256_mul_mod(&cur, &cur, &cur);
            w >>= 1;
        }
    }
    *res = out;
}

static int u256_eq(const u256 *a, const u256 *b) {
    return a->d[0] == b->d[0] && a->d[1] == b->d[1] && a->d[2] == b->d[2] && a->d[3] == b->d[3];
}

static void point_double_affine(PointAffine *r, const PointAffine *p) {
    u256 three, xx, num, den, inv, lam, lam2, t;
    xx = p->X;
    u256_mul_mod(&xx, &p->X, &p->X);
    three = (u256){ { 3, 0, 0, 0 } };
    u256_mul_mod(&num, &xx, &three);
    u256_add_mod(&den, &p->Y, &p->Y);
    u256_inv_mod(&inv, &den);
    u256_mul_mod(&lam, &num, &inv);
    u256_mul_mod(&lam2, &lam, &lam);
    u256_sub_mod(&t, &lam2, &p->X);
    u256_sub_mod(&r->X, &t, &p->X);
    u256_sub_mod(&t, &p->X, &r->X);
    u256_mul_mod(&t, &lam, &t);
    u256_sub_mod(&r->Y, &t, &p->Y);
}

static void point_add_affine(PointAffine *r, const PointAffine *p1, const PointAffine *p2) {
    if (u256_eq(&p1->X, &p2->X)) {
        u256 neg;
        u256_sub_mod(&neg, &(u256){{0}}, &p2->Y);
        if (u256_eq(&p1->Y, &neg)) {
            memset(r, 0, sizeof(*r));
            return;
        }
        point_double_affine(r, p1);
        return;
    }
    u256 dy, dx, inv, lam, lam2, t;
    u256_sub_mod(&dy, &p2->Y, &p1->Y);
    u256_sub_mod(&dx, &p2->X, &p1->X);
    u256_inv_mod(&inv, &dx);
    u256_mul_mod(&lam, &dy, &inv);
    u256_mul_mod(&lam2, &lam, &lam);
    u256_sub_mod(&t, &lam2, &p1->X);
    u256_sub_mod(&r->X, &t, &p2->X);
    u256_sub_mod(&t, &p1->X, &r->X);
    u256_mul_mod(&t, &lam, &t);
    u256_sub_mod(&r->Y, &t, &p1->Y);
}

static void point_mul_G(PointAffine *res, const u256 *scalar) {
    PointAffine acc = { { {0} }, { {0} } };
    int have = 0;
    PointAffine addend = { SECP256K1_GX, SECP256K1_GY };
    for (int word = 0; word < 4; word++) {
        uint64_t w = scalar->d[word];
        for (int b = 0; b < 64; b++) {
