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
            if (w & 1) {
                if (!have) {
                    acc = addend;
                    have = 1;
                } else {
                    PointAffine tmp;
                    point_add_affine(&tmp, &acc, &addend);
                    acc = tmp;
                }
            }
            PointAffine dbl;
            point_double_affine(&dbl, &addend);
            addend = dbl;
            w >>= 1;
        }
    }
    *res = acc;
}

/* --- hex / scalar helpers --- */
static int hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int parse_u256_hex(const char *hex, u256 *out) {
    while (*hex == '0' && *(hex + 1) == 'x') hex += 2;
    size_t len = strlen(hex);
    memset(out, 0, sizeof(*out));
    if (len == 0 || len > 64) return -1;
    uint8_t bytes[32] = {0};
    size_t pad = 64 - len;
    for (size_t i = 0; i < len; i++) {
        int n = hex_nibble(hex[i]);
        if (n < 0) return -1;
        size_t bi = (pad + i) / 2;
        if ((pad + i) % 2 == 0) bytes[bi] = (uint8_t)(n << 4);
        else bytes[bi] |= (uint8_t)n;
    }
    for (int i = 0; i < 4; i++) {
        uint64_t v = 0;
        for (int j = 0; j < 8; j++) v = (v << 8) | bytes[i * 8 + j];
        out->d[3 - i] = v;
    }
    return 0;
}

static void u256_to_hex(const u256 *v, char *out) {
    sprintf(out, "0x%016llx%016llx%016llx%016llx",
            (unsigned long long)v->d[3], (unsigned long long)v->d[2],
            (unsigned long long)v->d[1], (unsigned long long)v->d[0]);
    /* trim leading zeros after 0x */
    char *p = out + 2;
    while (*p == '0' && *(p + 1) != '\0') p++;
    if (p != out + 2) {
        memmove(out + 2, p, strlen(p) + 1);
    }
}

static int parse_pubkey(const char *hex, PointAffine *out) {
    while (*hex == '0' && *(hex + 1) == 'x') hex += 2;
    size_t len = strlen(hex);
    uint8_t raw[65];
    if (len != 66 && len != 130) return -1;
    for (size_t i = 0; i < len / 2; i++) {
        int hi = hex_nibble(hex[2 * i]);
        int lo = hex_nibble(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) return -1;
        raw[i] = (uint8_t)((hi << 4) | lo);
    }
    if (raw[0] == 0x04 && len == 130) {
        u256 x, y;
        char xhex[65], yhex[65];
        memcpy(xhex, hex + 2, 64); xhex[64] = 0;
        memcpy(yhex, hex + 66, 64); yhex[64] = 0;
        if (parse_u256_hex(xhex, &x) || parse_u256_hex(yhex, &y)) return -1;
        out->X = x;
        out->Y = y;
        return 0;
    }
    if ((raw[0] != 0x02 && raw[0] != 0x03) || len != 66) return -1;
    char xhex[65];
    memcpy(xhex, hex + 2, 64); xhex[64] = 0;
    if (parse_u256_hex(xhex, &out->X)) return -1;
    /* y^2 = x^3 + 7 ; y = (y2)^((p+1)/4) */
    u256 x2, x3, y2, y, seven = { { 7, 0, 0, 0 } };
    u256_mul_mod(&x2, &out->X, &out->X);
    u256_mul_mod(&x3, &x2, &out->X);
    u256_add_mod(&y2, &x3, &seven);
    /* exp = (p+1)/4 */
    u256 exp = { { 0xFFFFFFFFBFFFFF0CULL / 4, 0, 0, 0 } }; /* wrong — use full */
    /* (p+1)/4 = 0x3fffffffffffffffffffffffffffffffffffffffffffffffffffffffbfffff0c */
    exp = (u256){ {
        0xFFFFFFFFBFFFFF0CULL,
        0xFFFFFFFFFFFFFFFFULL,
        0xFFFFFFFFFFFFFFFFULL,
        0x3FFFFFFFFFFFFFFFULL
    } };
    y = (u256){ { 1, 0, 0, 0 } };
    u256 cur = y2;
    for (int word = 0; word < 4; word++) {
        uint64_t w = exp.d[word];
        for (int b = 0; b < 64; b++) {
            if (w & 1) u256_mul_mod(&y, &y, &cur);
            u256_mul_mod(&cur, &cur, &cur);
            w >>= 1;
        }
    }
    int odd = (int)(y.d[0] & 1ULL);
    int want_odd = (raw[0] == 0x03);
    if (odd != want_odd) u256_sub_mod(&y, &(u256){{0}}, &y);
    out->Y = y;
    return 0;
}

/* FNV-1a style hash of X for jump index — avoid SHA dep */
static unsigned jump_idx(const PointAffine *pt, unsigned table_len) {
    uint64_t h = 14695981039346656037ULL;
    for (int i = 0; i < 4; i++) {
        uint64_t w = pt->X.d[i];
        for (int b = 0; b < 8; b++) {
            h ^= (w & 0xff);
            h *= 1099511628211ULL;
            w >>= 8;
        }
    }
    return (unsigned)(h % table_len);
}

static int is_dp(const PointAffine *pt, unsigned dp_bits) {
    uint64_t mask = (dp_bits >= 64) ? ~0ULL : ((1ULL << dp_bits) - 1ULL);
    return (pt->X.d[0] & mask) == 0;
}

#define MAX_LOG 40
#define TAME_CAP 1 << 20

typedef struct {
    uint64_t x0; /* low 64 of X as key — collision-prone but ok for toy/bench */
    u256 dist;
    int used;
} TameSlot;

static TameSlot *g_tame;
static size_t g_tame_cap;

static void tame_init(size_t cap) {
    g_tame_cap = cap;
    g_tame = calloc(cap, sizeof(TameSlot));
}

static void tame_put(const PointAffine *pt, const u256 *dist) {
    uint64_t key = pt->X.d[0];
    size_t idx = (size_t)(key % g_tame_cap);
    for (size_t n = 0; n < 64; n++) {
        size_t i = (idx + n) % g_tame_cap;
        if (!g_tame[i].used || g_tame[i].x0 == key) {
            g_tame[i].used = 1;
            g_tame[i].x0 = key;
            g_tame[i].dist = *dist;
            return;
        }
    }
}

static int tame_get(const PointAffine *pt, u256 *dist_out) {
    uint64_t key = pt->X.d[0];
    size_t idx = (size_t)(key % g_tame_cap);
    for (size_t n = 0; n < 64; n++) {
        size_t i = (idx + n) % g_tame_cap;
        if (!g_tame[i].used) return 0;
        if (g_tame[i].x0 == key) {
            *dist_out = g_tame[i].dist;
            return 1;
        }
    }
    return 0;
}

static void u256_add_n(u256 *res, const u256 *a, uint64_t n) {
    __uint128_t c = (__uint128_t)a->d[0] + n;
    res->d[0] = (uint64_t)c; c >>= 64;
    c += a->d[1]; res->d[1] = (uint64_t)c; c >>= 64;
    c += a->d[2]; res->d[2] = (uint64_t)c; c >>= 64;
    c += a->d[3]; res->d[3] = (uint64_t)c;
}

static void u256_from_u64(u256 *o, uint64_t v) {
    memset(o, 0, sizeof(*o));
    o->d[0] = v;
}

static void write_status(const char *path, int running, uint64_t steps, double elapsed,
                         int found, const char *key_hex, double ops_s, int dp_tame) {
    FILE *fp = fopen(path, "w");
    if (!fp) return;
    fprintf(fp,
            "{\"running\":%s,\"steps\":%llu,\"elapsed\":%.3f,\"found\":%s,"
            "\"key_hex\":%s%s%s,\"ops_per_s\":%.0f,\"dp_tame\":%d,\"engine\":\"kangaroo_c\"}\n",
            running ? "true" : "false",
            (unsigned long long)steps, elapsed,
            found ? "true" : "false",
            found ? "\"" : "null",
            found ? key_hex : "",
            found ? "\"" : "",
            ops_s, dp_tame);
    fclose(fp);
}

static double now_s(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec * 1e-9;
}

static int kangaroo_run(const PointAffine *target, const u256 *lo, const u256 *hi,
                        uint64_t limit, const char *status_path, int verify_toy_secret,
                        uint64_t toy_secret) {
