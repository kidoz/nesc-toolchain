#ifndef NESC_COLLISION_H
#define NESC_COLLISION_H

/*
 * Tile-grid collision map at 8x8-pixel granularity covering the whole
 * 256x240 frame: 32 columns x 30 rows of material bytes in RAM (960 bytes).
 * Header-only: the grid and helpers compile into the including translation
 * unit.
 *
 * Material 0 conventionally means "empty"; other values are game-defined
 * (brick, concrete, water, forest, ...). Populate the grid at stage load
 * (from T3 `const` ROM tables) with nes_collision_clear + nes_collision_set,
 * then query per frame:
 *   nes_collision_at(x, y)           material under one pixel
 *   nes_collision_box(x, y, w, h)    bitwise OR of the materials under the
 *                                    four corners of a box; exact for boxes
 *                                    up to 16x16 pixels (Battle City tanks)
 */

static u8 __nes_collision_grid[960];

static void nes_collision_clear(u8 material) {
    u16 index;
    for (index = 0u16; index < 960u16; index++) {
        __nes_collision_grid[index] = material;
    }
}

static void nes_collision_set(u8 tile_x, u8 tile_y, u8 material) {
    __nes_collision_grid[((u16)tile_y << 5u8) + (u16)tile_x] = material;
}

static u8 nes_collision_tile(u8 tile_x, u8 tile_y) {
    return __nes_collision_grid[((u16)tile_y << 5u8) + (u16)tile_x];
}

static u8 nes_collision_at(u8 x, u8 y) {
    return nes_collision_tile(x >> 3u8, y >> 3u8);
}

static u8 nes_collision_box(u8 x, u8 y, u8 width, u8 height) {
    u8 right = x + width - 1u8;
    u8 bottom = y + height - 1u8;
    return nes_collision_at(x, y) | nes_collision_at(right, y) | nes_collision_at(x, bottom)
        | nes_collision_at(right, bottom);
}

#endif
