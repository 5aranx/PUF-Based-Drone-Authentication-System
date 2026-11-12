#pragma once
/*
 * BCH(255, 131, t=18) over GF(2^8)
 *
 * Parameters:
 *   n = 255  (codeword length in bits)
 *   k = 131  (data bits)
 *   t = 18   (error correction capability)
 *   n-k = 124 parity bits
 *
 * Primitive polynomial: x^8 + x^4 + x^3 + x^2 + 1  (0x11D)
 * Generator polynomial: product of minimal polynomials of alpha^i for
 *   i = 1,3,5,...,35  (2t-1 = 35 odd powers, t=18)
 *   degree(g) = 124
 *
 * Encoding is systematic: data occupies bits [0..130], parity bits [131..254]
 * All 255-bit values are stored in 32 bytes (MSB first, top bit of byte[0] is
 * bit 254; the top (unused) bit of the 32-byte buffer is always zero).
 */

#include <stdint.h>

#define BCH_N        255   /* codeword bits */
#define BCH_K        131   /* data bits     */
#define BCH_T        18    /* error cap     */
#define BCH_NPARITY  124   /* parity bits = N - K */
#define BCH_BYTES    32    /* ceil(255/8)   */

/* GF(2^8) element type */
typedef uint8_t gf_t;

/*
 * BCH context.  Initialise once with bch_init(); then reuse for
 * multiple encode/decode operations.
 */
typedef struct {
    /* GF(2^8) lookup tables */
    gf_t  gf_exp[512];   /* alpha^i,  index i in [0,510]; exp[i]=exp[i+255] */
    int   gf_log[256];   /* log_alpha(x); gf_log[0] = -1 (undefined)        */

    /* Generator polynomial coefficients g[0..BCH_NPARITY]
     * g[0] = 1 (leading), g[BCH_NPARITY] = constant term
     * Stored as GF elements (each is 0 or a power of alpha for GF(2^8),
     * but since all minimal poly coefficients are 0/1 and g is a product
     * over GF(2), every g[i] is 0 or 1 — stored as uint8_t for uniformity) */
    uint8_t g[BCH_NPARITY + 1];   /* degree-124 poly, 125 coefficients */
} bch_ctx_t;

/*
 * Initialise BCH context: build GF tables and generator polynomial.
 * Must be called before encode/decode.
 */
void bch_init(bch_ctx_t *ctx);

/*
 * Systematic BCH encode.
 *
 *   data      – pointer to ceil(data_bits/8) bytes of input (MSB first)
 *   data_bits – number of valid data bits (must equal BCH_K = 131)
 *   codeword  – output buffer of BCH_BYTES = 32 bytes; receives the
 *               full 255-bit systematic codeword (data | parity)
 *
 * The top unused bit (bit 255 of a 256-bit buffer) is always cleared.
 */
void bch_encode(bch_ctx_t *ctx,
                const uint8_t *data, int data_bits,
                uint8_t *codeword);

/*
 * In-place BCH decode.
 *
 *   codeword         – 32-byte buffer containing the (possibly corrupted)
 *                      255-bit codeword; corrected in-place on success
 *   errors_corrected – set to the number of bit errors found (may be NULL)
 *
 * Returns:
 *    0  – success (codeword corrected in-place; first 131 bits are data)
 *   -1  – uncorrectable error (more than t=18 bit errors, or decode failed)
 */
int bch_decode(bch_ctx_t *ctx,
               uint8_t *codeword,
               int *errors_corrected);
