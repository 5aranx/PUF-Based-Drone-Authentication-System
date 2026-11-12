#pragma once
/*
 * fuzzy_extractor.h – BCH code-offset fuzzy extractor
 *
 * Construction (Dodis et al. code-offset):
 *
 *   Enroll:
 *     Given PUF reading P (255 bits) and desired key K (128 bits):
 *       1. Encode K as first 128 bits of a 255-bit buffer (pad with zeros)
 *       2. BCH-encode → codeword C  (255 bits)
 *       3. Helper data H = P XOR C  (255 bits, stored as 32 bytes)
 *
 *   Reconstruct:
 *     Given noisy PUF reading P' and helper data H:
 *       1. C' = P' XOR H            (recovers a noisy version of C)
 *       2. BCH-decode C' → C        (corrects up to t=18 bit errors)
 *       3. K  = first 128 bits of C
 *
 * Security note:
 *   H is public (stored in flash).  Security relies on the min-entropy
 *   of P being sufficient: with 255 bits from SRAM PUF (each ~0.95 biased),
 *   the remaining entropy after releasing H is > 128 bits.
 */

#include <stdint.h>
#include "../../components/bch/bch.h"

#define FE_KEY_BYTES     16   /* 128-bit key                     */
#define FE_BLOCK_BITS    255  /* BCH(255,131,18) codeword length */
#define FE_BLOCK_BYTES   32   /* ceil(255/8)                     */
#define FE_HELPER_BYTES  32   /* helper data H (same size)       */

typedef struct {
    bch_ctx_t bch;
} fe_ctx_t;

/*
 * Initialise fuzzy extractor context (builds BCH GF tables and generator poly).
 * Call once at startup; reuse for enroll and all reconstruct calls.
 */
void fe_init(fe_ctx_t *ctx);

/*
 * Enrollment: given the stable PUF bits and a desired key, produce helper data.
 *
 *   p_selected  – 32 bytes, 255 valid bits (top bit of byte[0] is bit 254;
 *                 the unused 256th bit is ignored)
 *   key         – 16 bytes (128-bit key to protect)
 *   helper_out  – 32 bytes; receives public helper data H
 *
 * K is embedded as the first 128 bits of a BCH(255,131,18) codeword; the
 * remaining 127 data bits and 124 parity bits are computed by the encoder.
 * (The 3 extra data bits beyond 128 are set to zero for a clean decode.)
 */
void fe_enroll(fe_ctx_t *ctx,
               const uint8_t *p_selected,   /* 32 bytes, 255 valid bits */
               const uint8_t *key,          /* 16 bytes                 */
               uint8_t *helper_out);        /* 32 bytes                 */

/*
 * Reconstruction: given noisy PUF bits and stored helper data, recover key.
 *
 *   p_prime     – 32 bytes, current (noisy) PUF reading
 *   helper      – 32 bytes, helper data H stored during enrollment
 *   key_out     – 16 bytes; receives recovered key on success
 *
 * Returns:
 *    0  success
 *   -1  BCH decode failed (too many bit errors, or hardware fault)
 */
int fe_reconstruct(fe_ctx_t *ctx,
                   const uint8_t *p_prime,  /* 32 bytes */
                   const uint8_t *helper,   /* 32 bytes */
                   uint8_t *key_out);       /* 16 bytes */
