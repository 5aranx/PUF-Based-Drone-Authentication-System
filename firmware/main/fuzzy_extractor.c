/*
 * fuzzy_extractor.c – BCH code-offset fuzzy extractor implementation
 *
 * See fuzzy_extractor.h for the construction overview.
 */

#include "fuzzy_extractor.h"
#include <string.h>

/* ---------------------------------------------------------------------------
 * fe_init
 * --------------------------------------------------------------------------- */
void fe_init(fe_ctx_t *ctx)
{
    bch_init(&ctx->bch);
}

/* ---------------------------------------------------------------------------
 * fe_enroll
 *
 * Steps:
 *   1. Build a BCH_K=131 bit data buffer:
 *        - bits [0..127]  = key K (16 bytes, MSB first)
 *        - bits [128..130] = 0 (padding to reach 131)
 *   2. BCH-encode to 255-bit codeword C
 *   3. H = P XOR C  (bitwise, 32 bytes; the top unused bit is 0^0=0)
 * --------------------------------------------------------------------------- */
void fe_enroll(fe_ctx_t *ctx,
               const uint8_t *p_selected,
               const uint8_t *key,
               uint8_t *helper_out)
{
    uint8_t data_buf[FE_BLOCK_BYTES]; /* 32 bytes, 255 bits used */
    uint8_t codeword[FE_BLOCK_BYTES];

    /*
     * Build the 131-bit data word:
     * First 16 bytes = key (128 bits), remaining bits zeroed.
     * We place this in a 32-byte buffer (top bit = bit 254, unused = 0).
     * The key occupies bits 0..127; bits 128..130 are zero; bits 131..254
     * will be overwritten by bch_encode with parity.
     */
    memset(data_buf, 0, sizeof(data_buf));
    memcpy(data_buf, key, FE_KEY_BYTES); /* bits 0..127 */
    /* bits 128..130 remain 0 (padding), bits 131..254 will be parity */

    /* BCH encode: data_buf carries the first BCH_K=131 bits as data */
    bch_encode(&ctx->bch, data_buf, BCH_K, codeword);

    /* H = P_selected XOR codeword */
    for (int i = 0; i < FE_BLOCK_BYTES; i++) {
        helper_out[i] = p_selected[i] ^ codeword[i];
    }
}

/* ---------------------------------------------------------------------------
 * fe_reconstruct
 *
 * Steps:
 *   1. C' = P'_selected XOR H      (recover noisy codeword)
 *   2. BCH_decode(C')              (correct up to t=18 bit errors in-place)
 *   3. key_out = first 128 bits of corrected C  (first 16 bytes)
 *   4. Return 0 on success, -1 on decode failure
 * --------------------------------------------------------------------------- */
int fe_reconstruct(fe_ctx_t *ctx,
                   const uint8_t *p_prime,
                   const uint8_t *helper,
                   uint8_t *key_out)
{
    uint8_t codeword_prime[FE_BLOCK_BYTES];
    int errors = 0;
    int rc;

    /* Step 1: recover noisy codeword */
    for (int i = 0; i < FE_BLOCK_BYTES; i++) {
        codeword_prime[i] = p_prime[i] ^ helper[i];
    }

    /* Step 2: BCH decode (in-place correction) */
    rc = bch_decode(&ctx->bch, codeword_prime, &errors);
    if (rc != 0) {
        /* Zeroize working buffer before returning */
        memset(codeword_prime, 0, sizeof(codeword_prime));
        return -1;
    }

    /* Step 3: extract first 128 bits (16 bytes) as the key */
    memcpy(key_out, codeword_prime, FE_KEY_BYTES);

    /* Zeroize working buffer */
    memset(codeword_prime, 0, sizeof(codeword_prime));

    return 0;
}
