#ifndef NESC_CONTROLLER_H
#define NESC_CONTROLLER_H

#define NES_BUTTON_A 0x80u8
#define NES_BUTTON_B 0x40u8
#define NES_BUTTON_SELECT 0x20u8
#define NES_BUTTON_START 0x10u8
#define NES_BUTTON_UP 0x08u8
#define NES_BUTTON_DOWN 0x04u8
#define NES_BUTTON_LEFT 0x02u8
#define NES_BUTTON_RIGHT 0x01u8

u8 nes_read_controller(u8 port);

#endif
