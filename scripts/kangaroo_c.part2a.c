
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
