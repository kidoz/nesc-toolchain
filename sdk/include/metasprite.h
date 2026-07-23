#ifndef NESC_METASPRITE_H
#define NESC_METASPRITE_H

#include <sprite.h>

/*
 * 16x16 metasprite composition over the shadow-OAM sprite primitives.
 * Header-only: helpers compile into the including translation unit.
 *
 * A metasprite occupies four consecutive hardware sprites starting at
 * `first_sprite` (0, 4, 8, ... keeps metasprites aligned but any index
 * works). Tiles are laid out row-major from `base_tile`:
 *   base_tile + 0  top-left      base_tile + 1  top-right
 *   base_tile + 2  bottom-left   base_tile + 3  bottom-right
 * which matches consecutive tiles exported by the CHR pipeline. All four
 * parts share one attribute byte (palette, priority, flips are per-part
 * concerns left to game code that needs them). Call nes_oam_dma() once per
 * frame after composing metasprites.
 */

static void nes_metasprite_draw(u8 first_sprite, u8 x, u8 y, u8 base_tile, u8 attributes) {
    nes_set_sprite_position(first_sprite, x, y);
    nes_set_sprite_tile(first_sprite, base_tile);
    nes_set_sprite_attributes(first_sprite, attributes);
    nes_set_sprite_position(first_sprite + 1u8, x + 8u8, y);
    nes_set_sprite_tile(first_sprite + 1u8, base_tile + 1u8);
    nes_set_sprite_attributes(first_sprite + 1u8, attributes);
    nes_set_sprite_position(first_sprite + 2u8, x, y + 8u8);
    nes_set_sprite_tile(first_sprite + 2u8, base_tile + 2u8);
    nes_set_sprite_attributes(first_sprite + 2u8, attributes);
    nes_set_sprite_position(first_sprite + 3u8, x + 8u8, y + 8u8);
    nes_set_sprite_tile(first_sprite + 3u8, base_tile + 3u8);
    nes_set_sprite_attributes(first_sprite + 3u8, attributes);
}

static void nes_metasprite_hide(u8 first_sprite) {
    /* Y = $FF parks the sprite below the visible frame. */
    nes_set_sprite_position(first_sprite, 0u8, 0xFFu8);
    nes_set_sprite_position(first_sprite + 1u8, 0u8, 0xFFu8);
    nes_set_sprite_position(first_sprite + 2u8, 0u8, 0xFFu8);
    nes_set_sprite_position(first_sprite + 3u8, 0u8, 0xFFu8);
}

#endif
