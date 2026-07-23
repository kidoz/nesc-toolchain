#ifndef NESC_UPDATE_H
#define NESC_UPDATE_H

#include <ppu.h>

/*
 * Vblank PPU update buffer. Header-only: the queue and helpers compile into
 * the including translation unit.
 *
 * Gameplay code cannot write VRAM while rendering is enabled, so it queues
 * address/value pairs with nes_update_queue during the frame and calls
 * nes_update_flush right after nes_wait_vblank, while the PPU is idle. The
 * queue holds 16 single-byte writes; nes_update_queue drops further entries
 * once full (check nes_update_pending to budget work across frames). Call
 * nes_update_reset once at startup before the first queue.
 */

static u8 __nes_update_count;
static u8 __nes_update_high[16];
static u8 __nes_update_low[16];
static u8 __nes_update_value[16];

static void nes_update_reset(void) {
    __nes_update_count = 0u8;
}

static u8 nes_update_pending(void) {
    return __nes_update_count;
}

static void nes_update_queue(u16 address, u8 value) {
    if (__nes_update_count < 16u8) {
        __nes_update_high[__nes_update_count] = (u8)(address >> 8u8);
        __nes_update_low[__nes_update_count] = (u8)address;
        __nes_update_value[__nes_update_count] = value;
        __nes_update_count = __nes_update_count + 1u8;
    }
}

static void nes_update_flush(void) {
    u8 index;
    for (index = 0u8; index < __nes_update_count; index++) {
        nes_set_ppu_address(((u16)__nes_update_high[index] << 8u8) | (u16)__nes_update_low[index]);
        nes_write_ppu_data(__nes_update_value[index]);
    }
    __nes_update_count = 0u8;
}

#endif
