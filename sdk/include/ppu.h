#ifndef NESC_PPU_H
#define NESC_PPU_H

void nes_enable_rendering(void);
void nes_disable_rendering(void);
void nes_set_background_color(u8 color);
void nes_set_ppu_address(u16 address);
void nes_write_ppu_data(u8 value);

#endif
