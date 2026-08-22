/* Exact Pollard Kangaroo source is split across kangaroo_c_p1.inc +
 * kangaroo_c_p2.inc (byte-identical to the monolithic kangaroo_c.c).
 * Build (from repo root): gcc -O3 -o scripts/kangaroo scripts/kangaroo_c.c
 */
#include "kangaroo_c_p1.inc"
#include "kangaroo_c_p2.inc"
