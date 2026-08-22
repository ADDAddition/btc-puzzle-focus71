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
