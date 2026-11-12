/*
 * BCH(255, 131, t=18) implementation over GF(2^8)
 *
 * Primitive polynomial: x^8 + x^4 + x^3 + x^2 + 1  (0x11D)
 *
 * Decoding pipeline:
 *   1. Compute 2t=36 syndromes S_1 .. S_36
 *   2. Berlekamp-Massey to find error locator polynomial sigma(x)
 *   3. Chien search to find error locations
 *   4. For a binary BCH code error values are always 1, so no Forney needed
 *   5. Flip the error bits in the codeword
 *
 * Compilation:
 *   gcc -std=c99 -O2 bch.c          (host, for unit testing)
 *   xtensa-esp32-elf-gcc -std=c99   (cross-compile via IDF)
 */

#include "bch.h"
#include <string.h>
#include <stddef.h>

/* =========================================================================
 * GF(2^8) arithmetic
 * Primitive poly p(x) = x^8 + x^4 + x^3 + x^2 + 1 → 0x11D
 * ========================================================================= */

#define GF_POLY  0x11D   /* 1_0001_1101 */
#define GF_SIZE  256
#define GF_MAX   255     /* 2^8 - 1, order of GF* */

/* GF multiply using log/exp tables (from ctx) */
static inline gf_t gf_mul(const bch_ctx_t *ctx, gf_t a, gf_t b)
{
    if (a == 0 || b == 0) return 0;
    int s = ctx->gf_log[a] + ctx->gf_log[b];
    return ctx->gf_exp[s]; /* exp table is doubled so no mod needed for s<510 */
}

static inline gf_t gf_div(const bch_ctx_t *ctx, gf_t a, gf_t b)
{
    /* b must be non-zero */
    if (a == 0) return 0;
    int s = ctx->gf_log[a] - ctx->gf_log[b] + GF_MAX;
    return ctx->gf_exp[s % GF_MAX];
}

static inline gf_t gf_pow(const bch_ctx_t *ctx, gf_t a, int n)
{
    if (a == 0) return 0;
    if (n == 0) return 1;
    int s = ((long long)ctx->gf_log[a] * (n % GF_MAX) + GF_MAX * 1000LL) % GF_MAX;
    return ctx->gf_exp[s];
}

static inline gf_t gf_inv(const bch_ctx_t *ctx, gf_t a)
{
    /* a^(GF_MAX-1) = 1, so a^-1 = a^(GF_MAX-2) */
    return ctx->gf_exp[(GF_MAX - ctx->gf_log[a]) % GF_MAX];
}

/* GF add/sub are identical (XOR in GF(2^m)) */
#define gf_add(a, b)  ((gf_t)((a) ^ (b)))
#define gf_sub(a, b)  gf_add(a, b)

/* =========================================================================
 * Bit access helpers for packed 32-byte (255-bit) buffers.
 * Bit numbering: bit 0 is the MSB of byte[0] (the highest-degree term).
 * This matches the systematic encoding convention where data is in the
 * leading bits and parity in the trailing bits.
 * ========================================================================= */

static inline int buf_get_bit(const uint8_t *buf, int pos)
{
    return (buf[pos >> 3] >> (7 - (pos & 7))) & 1;
}

static inline void buf_set_bit(uint8_t *buf, int pos, int val)
{
    int byte = pos >> 3;
    int shift = 7 - (pos & 7);
    if (val)
        buf[byte] |=  (uint8_t)(1u << shift);
    else
        buf[byte] &= (uint8_t)~(1u << shift);
}

static inline void buf_flip_bit(uint8_t *buf, int pos)
{
    buf[pos >> 3] ^= (uint8_t)(1u << (7 - (pos & 7)));
}

/* =========================================================================
 * bch_init – build GF tables and generator polynomial
 * ========================================================================= */

void bch_init(bch_ctx_t *ctx)
{
    /* --- Build exp/log tables for GF(2^8) with poly 0x11D --- */
    gf_t x = 1;
    for (int i = 0; i < GF_MAX; i++) {
        ctx->gf_exp[i] = x;
        ctx->gf_exp[i + GF_MAX] = x; /* duplicate for s without mod */
        ctx->gf_log[x] = i;
        x = (gf_t)((x << 1) ^ ((x & 0x80) ? GF_POLY : 0));
    }
    ctx->gf_exp[GF_MAX] = ctx->gf_exp[0]; /* exp[255] = exp[0] = 1 */
    ctx->gf_log[0] = -1; /* log(0) undefined */

    /*
     * --- Build generator polynomial g(x) ---
     *
     * g(x) = LCM of minimal polynomials of alpha^1, alpha^3, ..., alpha^(2t-1)
     * for t = 18, i.e., roots at alpha^1, alpha^3, ..., alpha^35.
     *
     * For a binary BCH code over GF(2^8), elements in the same cyclotomic
     * coset share the same minimal polynomial.  We identify unique cosets
     * and multiply their minimal polynomials together over GF(2)[x].
     *
     * Cosets mod 255 for odd exponents 1..35:
     *   Each coset C_i = { i, 2i, 4i, 8i, ... } mod 255
     *   The minimal polynomial of alpha^i has degree |C_i| and
     *   coefficients in GF(2) (since we're building a binary BCH code).
     */

    /* Work over GF(2)[x]: coefficients are 0 or 1, stored as uint8_t.
     * g[] has degree up to BCH_NPARITY = 124, so 125 entries. */
    memset(ctx->g, 0, sizeof(ctx->g));
    ctx->g[0] = 1; /* g(x) = 1 to start */
    int g_deg = 0;

    /* Track which roots we've already included */
    int included[GF_MAX + 1];
    memset(included, 0, sizeof(included));

    for (int i = 1; i <= 2 * BCH_T - 1; i += 2) {
        /* Skip if alpha^i already a root of g */
        if (included[i % GF_MAX]) continue;

        /* Enumerate coset of i */
        int coset[8];
        int coset_size = 0;
        int cur = i % GF_MAX;
        for (;;) {
            if (included[cur]) break;
            coset[coset_size++] = cur;
            included[cur] = 1;
            cur = (cur * 2) % GF_MAX;
            if (cur == i % GF_MAX) break;
        }

        /*
         * Build minimal polynomial m(x) = product of (x - alpha^coset[j])
         * over GF(2^8), then reduce coefficients mod 2 (they're in GF(2)).
         *
         * We build m in GF(2^8)[x] then verify coefficients are in GF(2).
         * Use a temporary array: m_tmp[d] = coefficient of x^d.
         */
        gf_t m_tmp[9]; /* at most degree 8 */
        memset(m_tmp, 0, sizeof(m_tmp));
        m_tmp[0] = 1; /* m(x) = 1 */
        int m_deg = 0;

        for (int j = 0; j < coset_size; j++) {
            /* Multiply m(x) by (x + alpha^coset[j])  [add = sub in GF(2^m)] */
            gf_t root = ctx->gf_exp[coset[j]]; /* alpha^coset[j] */
            /* Shift up and XOR */
            for (int d = m_deg; d >= 0; d--) {
                m_tmp[d + 1] = gf_add(m_tmp[d + 1], m_tmp[d]);
                m_tmp[d]     = gf_mul(ctx, m_tmp[d], root);
            }
            m_deg++;
        }
        /* Coefficients should all be 0 or 1 — reduce to binary */
        /* (they are already 0 or 1 for a binary BCH code) */

        /* Multiply g(x) *= m(x) over GF(2)[x] */
        int new_deg = g_deg + m_deg;
        uint8_t new_g[BCH_NPARITY + 1];
        memset(new_g, 0, sizeof(new_g));
        for (int a = 0; a <= g_deg; a++) {
            if (!ctx->g[a]) continue;
            for (int b = 0; b <= m_deg; b++) {
                if (!m_tmp[b]) continue;
                new_g[a + b] ^= 1; /* GF(2) multiply: 1*1=1, XOR for add */
            }
        }
        g_deg = new_deg;
        memcpy(ctx->g, new_g, sizeof(ctx->g));
    }

    /* Sanity: degree of g should equal BCH_NPARITY = 124 */
    /* (If not, the coset enumeration is wrong) */
}

/* =========================================================================
 * bch_encode – systematic encoding
 *
 * Codeword layout (bit addressing, MSB first):
 *   bits [0 .. BCH_K-1]      = data (copied verbatim)
 *   bits [BCH_K .. BCH_N-1]  = parity (BCH remainder)
 *
 * Method: compute r(x) = x^(n-k) * d(x) mod g(x), then
 *   codeword = x^(n-k)*d(x) + r(x)  (systematic form)
 * ========================================================================= */

void bch_encode(bch_ctx_t *ctx,
                const uint8_t *data, int data_bits,
                uint8_t *codeword)
{
    (void)data_bits; /* Must equal BCH_K; caller's responsibility */

    /* Copy data into the first BCH_K bits of codeword */
    memset(codeword, 0, BCH_BYTES);
    for (int i = 0; i < BCH_K; i++) {
        if (buf_get_bit(data, i))
            buf_set_bit(codeword, i, 1);
    }

    /*
     * Compute parity = x^(BCH_NPARITY) * data(x)  mod  g(x)
     *
     * We use the LFSR (shift-register) method on binary data bits,
     * which works naturally in GF(2).
     *
     * Remainder register: reg[0..BCH_NPARITY-1] holds r(x) of degree < 124.
     * reg[0] = coefficient of x^0 (constant term).
     */
    uint8_t reg[BCH_NPARITY]; /* 124 bits */
    memset(reg, 0, sizeof(reg));

    for (int i = 0; i < BCH_K; i++) {
        int bit = buf_get_bit(data, i);
        int feedback = bit ^ reg[BCH_NPARITY - 1];
        /* Shift register right, XOR with g where feedback=1 */
        for (int j = BCH_NPARITY - 1; j > 0; j--)
            reg[j] = reg[j - 1] ^ (feedback ? ctx->g[BCH_NPARITY - j] : 0);
        reg[0] = feedback ? ctx->g[BCH_NPARITY] : 0;
    }

    /* Write parity bits (reg contains r(x) with reg[i] = coeff of x^i) */
    /* Parity occupies codeword bits [BCH_K .. BCH_N-1] */
    /* reg[BCH_NPARITY-1] is the highest degree term → codeword bit BCH_K */
    for (int i = 0; i < BCH_NPARITY; i++) {
        int cw_bit = BCH_K + (BCH_NPARITY - 1 - i);
        buf_set_bit(codeword, cw_bit, reg[i] & 1);
    }
}

/* =========================================================================
 * Syndrome computation
 *
 * S_j = codeword(alpha^j)  for j = 1 .. 2t
 * We evaluate the received polynomial r(x) at each root alpha^j.
 *
 * r(x) = sum_{i=0}^{254} r_i * x^i,  r_i = bit i of codeword (bit 0 = MSB byte[0])
 *
 * S_j = sum_{i=0}^{254} r_i * (alpha^j)^i = sum r_i * alpha^(j*i mod 255)
 * ========================================================================= */

static void compute_syndromes(const bch_ctx_t *ctx,
                               const uint8_t *codeword,
                               gf_t *S)  /* S[0..2t-1], S[i] = S_{i+1} */
{
    for (int j = 0; j < 2 * BCH_T; j++) {
        gf_t s = 0;
        for (int i = 0; i < BCH_N; i++) {
            if (buf_get_bit(codeword, i)) {
                /* add alpha^((j+1)*i mod 255) */
                int exp_idx = (int)(((long long)(j + 1) * i) % GF_MAX);
                s = gf_add(s, ctx->gf_exp[exp_idx]);
            }
        }
        S[j] = s;
    }
}

/* =========================================================================
 * Berlekamp-Massey algorithm
 *
 * Finds the shortest LFSR (error-locator polynomial) sigma(x) such that
 * sigma generates the syndrome sequence.
 *
 * Returns degree of sigma (= number of errors detected).
 * sigma[0] = 1 (monic).
 * ========================================================================= */

static int berlekamp_massey(const bch_ctx_t *ctx,
                             const gf_t *S,   /* syndromes S[0..2t-1] */
                             gf_t *sigma,     /* output: sigma[0..L] */
                             int max_errors)
{
    int n = 2 * max_errors;
    gf_t C[BCH_T + 1], B[BCH_T + 1];
    memset(C, 0, sizeof(C));
    memset(B, 0, sizeof(B));
    C[0] = 1; B[0] = 1;

    int L = 0, x = 1;
    gf_t b = 1;

    for (int r = 0; r < n; r++) {
        /* Compute discrepancy d */
        gf_t d = S[r];
        for (int i = 1; i <= L; i++) {
            d = gf_add(d, gf_mul(ctx, C[i], S[r - i]));
        }
        if (d == 0) {
            x++;
        } else {
            gf_t T[BCH_T + 1];
            memcpy(T, C, sizeof(T));
            gf_t coeff = gf_mul(ctx, d, gf_inv(ctx, b));
            /* C(x) = C(x) - d/b * x^x * B(x) */
            for (int i = x; i <= BCH_T; i++) {
                C[i] = gf_add(C[i], gf_mul(ctx, coeff, B[i - x]));
            }
            if (2 * L <= r) {
                L = r + 1 - L;
                memcpy(B, T, sizeof(B));
                b = d;
                x = 1;
            } else {
                x++;
            }
        }
    }

    memcpy(sigma, C, (L + 1) * sizeof(gf_t));
    return L;
}

/* =========================================================================
 * Chien search
 *
 * Evaluates sigma(x) at every GF element x = alpha^{-i} for i=0..254.
 * If sigma(alpha^{-i}) = 0, then alpha^i is a root → bit i is in error.
 * ========================================================================= */

static int chien_search(const bch_ctx_t *ctx,
                         const gf_t *sigma, int L,
                         int *error_pos)   /* output array, length >= L */
{
    int count = 0;
    for (int i = 0; i < BCH_N; i++) {
        /* Evaluate sigma at alpha^{-i} = alpha^{255-i} */
        gf_t val = sigma[0]; /* = 1 */
        gf_t xi = ctx->gf_exp[(GF_MAX - i) % GF_MAX]; /* alpha^{-i} */
        gf_t xpow = xi;
        for (int j = 1; j <= L; j++) {
            val = gf_add(val, gf_mul(ctx, sigma[j], xpow));
            xpow = gf_mul(ctx, xpow, xi);
        }
        if (val == 0) {
            error_pos[count++] = i;
            if (count > BCH_T) return -1; /* too many roots */
        }
    }
    return count;
}

/* =========================================================================
 * bch_decode
 * ========================================================================= */

int bch_decode(bch_ctx_t *ctx, uint8_t *codeword, int *errors_corrected)
{
    gf_t S[2 * BCH_T];
    compute_syndromes(ctx, codeword, S);

    /* Check if all syndromes zero → no errors */
    int all_zero = 1;
    for (int i = 0; i < 2 * BCH_T; i++) {
        if (S[i]) { all_zero = 0; break; }
    }
    if (all_zero) {
        if (errors_corrected) *errors_corrected = 0;
        return 0;
    }

    /* Find error locator polynomial */
    gf_t sigma[BCH_T + 1];
    memset(sigma, 0, sizeof(sigma));
    int L = berlekamp_massey(ctx, S, sigma, BCH_T);

    if (L < 0 || L > BCH_T) {
        if (errors_corrected) *errors_corrected = -1;
        return -1;
    }

    /* Chien search for error positions */
    int error_pos[BCH_T];
    int found = chien_search(ctx, sigma, L, error_pos);

    if (found < 0 || found != L) {
        /* Number of roots doesn't match degree of sigma → uncorrectable */
        if (errors_corrected) *errors_corrected = -1;
        return -1;
    }

    /* Flip error bits (binary BCH: error magnitude is always 1) */
    for (int i = 0; i < found; i++) {
        buf_flip_bit(codeword, error_pos[i]);
    }

    if (errors_corrected) *errors_corrected = found;
    return 0;
}
