/*
 * puf.c – SRAM PUF implementation for ESP32
 *
 * The noinit region is declared in the linker script as a section that is
 * NOT zeroed on power-up, allowing the SRAM power-up pattern to be read.
 *
 * Platform notes:
 *   - ESP32: declare puf_noinit_region with __attribute__((section(".noinit")))
 *     The IDF linker script places .noinit in DRAM without initialisation.
 *   - Host gcc: the array is in BSS (zeroed), so the PUF will be all-zeros
 *     on the first run.  Fill it from an entropy source for simulation.
 */

#include "puf.h"
#include <string.h>
#include <stddef.h>

/* ---------------------------------------------------------------------------
 * noinit region: DO NOT initialise this variable.
 * On ESP32 this is the actual PUF entropy source.
 * On host the linker will zero it (fine for unit tests).
 * --------------------------------------------------------------------------- */
#ifdef __xtensa__
/* ESP32 / xtensa target: use ESP-IDF noinit attribute */
static uint8_t puf_noinit_region[PUF_RAW_BYTES]
    __attribute__((section(".noinit")));
#else
/* Host target: plain static array (zeroed by BSS; usable for unit tests) */
static uint8_t puf_noinit_region[PUF_RAW_BYTES];
#endif

/* ---------------------------------------------------------------------------
 * puf_read_raw
 *
 * Copies the noinit SRAM region into the caller's buffer.  The copy is done
 * byte-by-byte to prevent the compiler from optimising away the read.
 * --------------------------------------------------------------------------- */
void puf_read_raw(uint8_t *out, size_t len)
{
    if (len > PUF_RAW_BYTES) len = PUF_RAW_BYTES;
    /* volatile read to prevent compiler from eliding the memory access */
    const volatile uint8_t *src = (const volatile uint8_t *)puf_noinit_region;
    for (size_t i = 0; i < len; i++) {
        out[i] = src[i];
    }
}

/* ---------------------------------------------------------------------------
 * puf_accumulate_votes
 *
 * For each bit in raw[], increment counters[bit_index] if the bit is 1.
 * state->boot_count must already have been incremented by the caller
 * before this function is called.
 * --------------------------------------------------------------------------- */
void puf_accumulate_votes(puf_vote_state_t *state,
                          const uint8_t *raw, size_t len)
{
    if (len > PUF_RAW_BYTES) len = PUF_RAW_BYTES;
    size_t total_bits = len * 8;
    for (size_t bit = 0; bit < total_bits; bit++) {
        uint8_t byte_val = raw[bit >> 3];
        int     shift    = 7 - (int)(bit & 7); /* MSB first */
        if ((byte_val >> shift) & 1u) {
            state->counters[bit]++;
        }
    }
}

/* ---------------------------------------------------------------------------
 * puf_finalise
 *
 * After PUF_N_VOTES boots have been accumulated:
 *   stable[bit] = 1  iff counters[bit] > boot_count/2  (majority vote)
 *   mask[bit]   = 1  iff counters[bit] == 0 OR counters[bit] == boot_count
 *                (the bit never flipped across all boot cycles)
 *
 * Both stable[] and mask[] are stored as bit-packed bytes, MSB first.
 * --------------------------------------------------------------------------- */
void puf_finalise(puf_vote_state_t *state)
{
    uint32_t n = state->boot_count;
    uint32_t half = n / 2; /* majority threshold */

    memset(state->stable, 0, PUF_RAW_BYTES);
    memset(state->mask,   0, PUF_RAW_BYTES);

    size_t total_bits = PUF_RAW_BYTES * 8;
    for (size_t bit = 0; bit < total_bits; bit++) {
        uint16_t cnt = state->counters[bit];
        int byte  = (int)(bit >> 3);
        int shift = 7 - (int)(bit & 7);

        /* Majority vote for stable value */
        if (cnt > half) {
            state->stable[byte] |= (uint8_t)(1u << shift);
        }

        /* Mask: bit is stable only if it never flipped */
        if (cnt == 0 || cnt == (uint16_t)n) {
            state->mask[byte] |= (uint8_t)(1u << shift);
        }
    }
}

/* ---------------------------------------------------------------------------
 * puf_select_bits
 *
 * Scans through stable[]/mask[] and picks the first (sel_bytes * 8) bits
 * where mask indicates stability.  Packs them MSB-first into selected[].
 *
 * If fewer than sel_bytes*8 stable bits exist, the remaining output bits
 * are zero (the caller should check that enough stable bits are available).
 * --------------------------------------------------------------------------- */
void puf_select_bits(const uint8_t *stable, const uint8_t *mask,
                     size_t len,
                     uint8_t *selected, size_t sel_bytes)
{
    memset(selected, 0, sel_bytes);
    size_t total_bits  = len * 8;
    size_t target_bits = sel_bytes * 8;
    size_t out_bit     = 0;

    for (size_t bit = 0; bit < total_bits && out_bit < target_bits; bit++) {
        int byte  = (int)(bit >> 3);
        int shift = 7 - (int)(bit & 7);

        /* Check mask */
        if (!((mask[byte] >> shift) & 1u)) continue;

        /* Stable bit: get its value from stable[] */
        int val = (stable[byte] >> shift) & 1;

        /* Write to selected output buffer */
        int out_byte  = (int)(out_bit >> 3);
        int out_shift = 7 - (int)(out_bit & 7);
        if (val) {
            selected[out_byte] |= (uint8_t)(1u << out_shift);
        }
        out_bit++;
    }
}
