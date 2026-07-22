#ifndef NESC_SPRITE_H
#define NESC_SPRITE_H

void nes_set_sprite_position(u8 sprite, u8 x, u8 y);
void nes_set_sprite_tile(u8 sprite, u8 tile);
void nes_set_sprite_attributes(u8 sprite, u8 attributes);
void nes_oam_dma(void);

#endif
