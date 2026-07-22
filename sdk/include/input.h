#ifndef NESC_INPUT_H
#define NESC_INPUT_H

#include <controller.h>

/*
 * Two-controller input with edge detection. Header-only: the state and helpers
 * compile into the including translation unit.
 *
 * Call nes_input_poll() once per frame (typically right after nes_wait_frame).
 * It shifts this frame's masks into the previous-frame slots and re-reads both
 * controllers, so nes_input_pressed / nes_input_released report transitions:
 *   held     = buttons down this frame
 *   pressed  = buttons that went down this frame  (current & ~previous)
 *   released = buttons that went up this frame     (previous & ~current)
 * Masks use the NES_BUTTON_* bit layout from <controller.h>.
 */

static u8 __nes_input_current_0;
static u8 __nes_input_current_1;
static u8 __nes_input_previous_0;
static u8 __nes_input_previous_1;

static void nes_input_poll(void) {
    __nes_input_previous_0 = __nes_input_current_0;
    __nes_input_previous_1 = __nes_input_current_1;
    __nes_input_current_0 = nes_read_controller(0u8);
    __nes_input_current_1 = nes_read_controller(1u8);
}

static u8 nes_input_held(u8 port) {
    if (port == 0u8) {
        return __nes_input_current_0;
    }
    return __nes_input_current_1;
}

/*
 * pressed/released are written with XOR rather than `current & ~previous`
 * because `a & (a ^ b)` equals `a & ~b` bit-for-bit and avoids the unary `~`
 * operator, whose 6502 lowering is currently defective.
 */
static u8 nes_input_pressed(u8 port) {
    if (port == 0u8) {
        return __nes_input_current_0 & (__nes_input_current_0 ^ __nes_input_previous_0);
    }
    return __nes_input_current_1 & (__nes_input_current_1 ^ __nes_input_previous_1);
}

static u8 nes_input_released(u8 port) {
    if (port == 0u8) {
        return __nes_input_previous_0 & (__nes_input_previous_0 ^ __nes_input_current_0);
    }
    return __nes_input_previous_1 & (__nes_input_previous_1 ^ __nes_input_current_1);
}

#endif
