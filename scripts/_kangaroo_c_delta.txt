    /* width approx from hi-lo using low limbs — for mean_log use bit length hint via args */
    unsigned mean_log = 16;
    /* estimate width bits from hi */
    unsigned hi_bits = 0;
    for (int i = 3; i >= 0; i--) {
        if (hi->d[i]) {
            hi_bits = (unsigned)(i * 64 + (64 - __builtin_clzll(hi->d[i])));
            break;
        }
    }
    mean_log = hi_bits / 2;
    if (mean_log < 8) mean_log = 8;
    if (mean_log > MAX_LOG) mean_log = MAX_LOG;
    unsigned dp_bits = mean_log / 5;
    if (dp_bits < 4) dp_bits = 4;

    PointAffine table[MAX_LOG];
    uint64_t jumps[MAX_LOG];
    table[0] = (PointAffine){ SECP256K1_GX, SECP256K1_GY };
    jumps[0] = 1;
    for (unsigned i = 1; i < mean_log; i++) {
        point_double_affine(&table[i], &table[i - 1]);
        jumps[i] = 1ULL << i;
    }

    tame_init(1 << 18);
    PointAffine t_pt;
    point_mul_G(&t_pt, hi);
    u256 t_dist = { {0} };
    PointAffine w_pt = *target;
    u256 w_dist = { {0} };

    double t0 = now_s();
    uint64_t steps = 0;
    int found = 0;
    u256 found_k = { {0} };
    const char *spath = status_path ? status_path : "/workspace/src/data/kangaroo_status.json";

    while (steps < limit && !found) {
        unsigned ti = jump_idx(&t_pt, mean_log);
        PointAffine nxt;
        point_add_affine(&nxt, &t_pt, &table[ti]);
        t_pt = nxt;
        u256_add_n(&t_dist, &t_dist, jumps[ti]);
        if (is_dp(&t_pt, dp_bits)) tame_put(&t_pt, &t_dist);

        unsigned wi = jump_idx(&w_pt, mean_log);
        point_add_affine(&nxt, &w_pt, &table[wi]);
        w_pt = nxt;
        u256_add_n(&w_dist, &w_dist, jumps[wi]);
        if (is_dp(&w_pt, dp_bits)) {
            u256 td;
            if (tame_get(&w_pt, &td)) {
                /* k ≈ hi + tame_dist - wild_dist (mod n) — low limbs for toy */
                __int128_t k = (__int128_t)hi->d[0] + (__int128_t)td.d[0] - (__int128_t)w_dist.d[0];
                if (k < 0) k += (__int128_t)SECP256K1_N.d[0]; /* insufficient for full n */
                if (verify_toy_secret && (uint64_t)k == toy_secret) {
                    found = 1;
                    u256_from_u64(&found_k, (uint64_t)k);
                } else if (!verify_toy_secret) {
                    /* verify k*G == target via point_mul_G for k fitting in 64b lo */
                    u256 cand;
                    memset(&cand, 0, sizeof(cand));
                    /* reconstruct: hi + td - wd using 128-bit on lo pair for ranges < 2^128 */
                    __uint128_t acc = ((__uint128_t)hi->d[1] << 64) | hi->d[0];
                    acc += ((__uint128_t)td.d[1] << 64) | td.d[0];
                    __uint128_t sub = ((__uint128_t)w_dist.d[1] << 64) | w_dist.d[0];
                    if (acc >= sub) acc -= sub;
                    else {
                        /* borrow from higher — rare in practice for interval kangaroo */
                        acc = acc - sub; /* wrap */
                    }
                    cand.d[0] = (uint64_t)acc;
                    cand.d[1] = (uint64_t)(acc >> 64);
                    PointAffine check;
                    point_mul_G(&check, &cand);
                    if (u256_eq(&check.X, &target->X) && u256_eq(&check.Y, &target->Y)) {
                        found = 1;
                        found_k = cand;
                    }
                }
            }
        }
        steps += 2;
        if ((steps & 0x3FFF) == 0) {
            double el = now_s() - t0;
            write_status(spath, 1, steps, el, 0, NULL, steps / (el > 0 ? el : 1), 0);
        }
    }

    double el = now_s() - t0;
    char kh[80] = "null";
    if (found) u256_to_hex(&found_k, kh);
    int dp_count = 0;
    for (size_t i = 0; i < g_tame_cap; i++) if (g_tame[i].used) dp_count++;
    write_status(spath, 0, steps, el, found, found ? kh : NULL, steps / (el > 0 ? el : 1), dp_count);
    printf("{\"found\":%s,\"steps\":%llu,\"elapsed\":%.3f,\"ops_per_s\":%.0f,\"dp_tame\":%d,\"key_hex\":%s%s%s}\n",
           found ? "true" : "false", (unsigned long long)steps, el,
           steps / (el > 0 ? el : 1), dp_count,
           found ? "\"" : "null", found ? kh : "", found ? "\"" : "");
    free(g_tame);
    return found ? 0 : 1;
}

static int cmd_bench(void) {
    PointAffine a = { SECP256K1_GX, SECP256K1_GY };
    PointAffine b = a;
    const int N = 20000;
    double t0 = now_s();
    for (int i = 0; i < N; i++) {
        PointAffine t;
        point_add_affine(&t, &a, &b);
        a = t;
    }
    double el = now_s() - t0;
    double ops = N / el;
    printf("{\"bench\":\"affine_add\",\"ops\":%d,\"elapsed\":%.4f,\"ops_per_s\":%.0f,\"engine\":\"kangaroo_c\"}\n",
           N, el, ops);
    FILE *fp = fopen("/workspace/src/data/kangaroo_status.json", "w");
    if (fp) {
        fprintf(fp, "{\"running\":false,\"bench\":true,\"ops_per_s\":%.0f,\"engine\":\"kangaroo_c\"}\n", ops);
        fclose(fp);
    }
    return 0;
}

static int cmd_toy(uint64_t limit) {
    /* secret in 2^24 window like Python --toy */
    uint64_t secret = 0x10000A5CD68ULL;
    u256 lo, hi, sec;
    parse_u256_hex("10000000000", &lo);
    parse_u256_hex("10000FFFFFF", &hi);
    u256_from_u64(&sec, secret);
    /* full secret needs high bits */
    sec.d[0] = secret;
    PointAffine target;
    point_mul_G(&target, &sec);
    printf("TOY secret=0x%llx range~2^24\n", (unsigned long long)secret);
    return kangaroo_run(&target, &lo, &hi, limit ? limit : 2000000ULL,
                        "/workspace/src/data/kangaroo_status.json", 1, secret);
}

int main(int argc, char **argv) {
    const char *pubkey = NULL;
    const char *lo_hex = NULL;
    const char *hi_hex = NULL;
    uint64_t limit = 5000000ULL;
    int toy = 0, bench = 0;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--bench")) bench = 1;
        else if (!strcmp(argv[i], "--toy")) toy = 1;
        else if (!strcmp(argv[i], "--pubkey") && i + 1 < argc) pubkey = argv[++i];
        else if (!strcmp(argv[i], "--lo") && i + 1 < argc) lo_hex = argv[++i];
        else if (!strcmp(argv[i], "--hi") && i + 1 < argc) hi_hex = argv[++i];
        else if (!strcmp(argv[i], "--limit") && i + 1 < argc) limit = strtoull(argv[++i], NULL, 10);
        else if (!strcmp(argv[i], "--help")) {
            fprintf(stderr, "Usage: kangaroo --bench | --toy | --pubkey HEX --lo HEX --hi HEX [--limit N]\n");
            return 0;
        }
    }

    if (bench) return cmd_bench();
    if (toy) return cmd_toy(limit);
    if (!pubkey || !lo_hex || !hi_hex) {
        fprintf(stderr, "Need --pubkey --lo --hi (or --toy / --bench)\n");
        return 2;
    }
    PointAffine target;
    u256 lo, hi;
    if (parse_pubkey(pubkey, &target)) {
        fprintf(stderr, "bad pubkey\n");
        return 2;
    }
    if (parse_u256_hex(lo_hex, &lo) || parse_u256_hex(hi_hex, &hi)) {
        fprintf(stderr, "bad lo/hi\n");
        return 2;
    }
    return kangaroo_run(&target, &lo, &hi, limit, "/workspace/src/data/kangaroo_status.json", 0, 0);
}
