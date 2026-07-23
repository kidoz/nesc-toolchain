#ifndef NESC_NAMETABLE_H
#define NESC_NAMETABLE_H

#include <ppu.h>

/*
 * Nametable, attribute, and palette helpers over the runtime PPU primitives.
 * Header-only: helpers compile into the including translation unit.
 *
 * All helpers write VRAM through $2006/$2007, so call them while rendering is
 * disabled or during vblank (for steady-state gameplay use <update.h> and
 * flush after nes_wait_vblank). PPUDATA auto-increments the VRAM address by
 * one, which the fill helpers rely on.
 *
 * Coordinates are in 8x8 tiles: x 0..31, y 0..29 of nametable 0 ($2000).
 * Attribute cells are the 8x8 grid of 32x32-pixel areas at $23C0.
 * Palette indices are 0..31 from $3F00 (0..15 background, 16..31 sprites).
 */

static u16 nes_nametable_address(u8 x, u8 y) {
    return 0x2000u16 + ((u16)y << 5u8) + (u16)x;
}

static void nes_set_tile(u8 x, u8 y, u8 tile) {
    nes_set_ppu_address(nes_nametable_address(x, y));
    nes_write_ppu_data(tile);
}

static void nes_fill_row(u8 y, u8 tile) {
    u8 column;
    nes_set_ppu_address(nes_nametable_address(0u8, y));
    for (column = 0u8; column < 32u8; column++) {
        nes_write_ppu_data(tile);
    }
}

static void nes_fill_rect(u8 x, u8 y, u8 width, u8 height, u8 tile) {
    u8 row;
    u8 column;
    for (row = 0u8; row < height; row++) {
        nes_set_ppu_address(nes_nametable_address(x, y + row));
        for (column = 0u8; column < width; column++) {
            nes_write_ppu_data(tile);
        }
    }
}

static void nes_set_attribute(u8 cell, u8 value) {
    nes_set_ppu_address(0x23C0u16 + (u16)cell);
    nes_write_ppu_data(value);
}

static void nes_set_palette_color(u8 index, u8 color) {
    nes_set_ppu_address(0x3F00u16 + (u16)index);
    nes_write_ppu_data(color);
}

#endif
