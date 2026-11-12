#pragma once
/*
 * puf.h – SRAM PUF interface for ESP32
 *
 * The PUF (Physically Unclonable Function) exploits the random power-up
 * state of uninitialized SRAM.  Because SRAM cells have manufacturing
 * variations, each chip produces a unique but reproducible bit pattern.
 *
 * To deal with noise (some bits flip across power cycles), we accumulate
 * votes over PUF_N_VOTES power cycles:
 *   – A bit that is always 0 or always 1 is "stable" and included.
 *   – A bit that sometimes flips is excluded via the mask.
 *
 * The vote state lives in RTC NOINIT memory so it survives esp_restart().
 */

#include <stdint.h>
#include <stddef.h>

#define PUF_RAW_BYTES   512   /* noinit SRAM region (512 bytes = 4096 bits) */
#define PUF_N_VOTES     32    /* number of power cycles for majority vote    */
#define PUF_SELECTED    32    /* bytes = 256 bits → take top 255 for BCH    */

/*
 * Persistent across esp_restart() via RTC_NOINIT_ATTR.
 * On real hardware, place with RTC_NOINIT_ATTR in main.c.
 */
typedef struct {
    uint32_t boot_count;                   /* number of voting boots so far */
    uint16_t counters[PUF_RAW_BYTES * 8]; /* per-bit 1-vote tallies         */
    uint8_t  stable[PUF_RAW_BYTES];       /* majority-voted stable values   */
    uint8_t  mask[PUF_RAW_BYTES];         /* 1 = bit is stable (never flips)*/
} puf_vote_state_t;

/*
 * Read the noinit SRAM PUF region into out[0..len-1].
 * On real hardware the region is mapped by the linker; on host sim
 * the buffer content is whatever was already there (entropy source).
 */
void puf_read_raw(uint8_t *out, size_t len);

/*
 * Accumulate one power-cycle reading into the vote counters.
 * Call once per boot before calling puf_finalise.
 */
void puf_accumulate_votes(puf_vote_state_t *state,
                          const uint8_t *raw, size_t len);

/*
 * Finalise voting: compute stable[] and mask[] from the counters.
 * Call once after all PUF_N_VOTES boots have been accumulated.
 */
void puf_finalise(puf_vote_state_t *state);

/*
 * Select the first sel_bytes*8 stable bits from stable[], guided by mask[].
 * Packs them MSB-first into selected[0..sel_bytes-1].
 */
void puf_select_bits(const uint8_t *stable, const uint8_t *mask,
                     size_t len,
                     uint8_t *selected, size_t sel_bytes);
