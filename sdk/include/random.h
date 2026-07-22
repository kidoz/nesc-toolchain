#ifndef NESC_RANDOM_H
#define NESC_RANDOM_H

/*
 * Deterministic 16-bit xorshift pseudo-random generator.
 *
 * Header-only: the state and helpers are compiled into the including
 * translation unit. The state lives in RAM and must be seeded with a NONZERO
 * value through nes_srand before nes_rand is used -- an all-zero state is a
 * fixed point of the xorshift and would never advance. The sequence is fully
 * deterministic, so it reproduces under `nesc run --hash` and `nesc test`.
 */

static u16 __nes_random_state;

static void nes_srand(u16 seed) {
    __nes_random_state = seed;
}

static u16 nes_rand(void) {
    u16 value = __nes_random_state;
    value = value ^ (value << 7u8);
    value = value ^ (value >> 9u8);
    value = value ^ (value << 8u8);
    __nes_random_state = value;
    return value;
}

static u8 nes_rand8(void) {
    return (u8)nes_rand();
}

#endif
