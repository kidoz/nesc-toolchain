#ifndef NESC_NES_H
#define NESC_NES_H

#include <audio.h>
#include <controller.h>
#include <mapper.h>
#include <ppu.h>
#include <sprite.h>

#define NES_MAIN __nesc_attribute__(main)
#define NES_RESET __nesc_attribute__(reset)
#define NES_NMI __nesc_attribute__(nmi)
#define NES_IRQ __nesc_attribute__(irq)
#define NES_ZEROPAGE __nesc_attribute__(zero_page)
#define NES_FIXED_BANK __nesc_attribute__(fixed_bank)
#define NES_BANK(number) __nesc_attribute__(bank, number)
#define NES_SEGMENT(name) __nesc_attribute__(segment, name)
#define NES_NOINLINE __nesc_attribute__(noinline)
#define NES_ALWAYS_INLINE __nesc_attribute__(always_inline)
#define NES_INTERRUPT_SAFE __nesc_attribute__(interrupt_safe)
#define NES_CYCLE_BUDGET(cycles) __nesc_attribute__(cycle_budget, cycles)
#define NES_OPTIMIZE_SIZE __nesc_attribute__(optimize_size)
#define NES_OPTIMIZE_CYCLES __nesc_attribute__(optimize_cycles)
#define NES_ALIGN(bytes) __nesc_attribute__(align, bytes)
#define NES_USED __nesc_attribute__(used)
#define NES_EXPORT __nesc_attribute__(export)
#define NES_IMPORT __nesc_attribute__(import)

/*
 * NES_ASM is reserved compiler syntax. Its contract items are
 * NES_ASM_INPUT_A/X/Y(value), NES_ASM_OUTPUT_A/X/Y(variable),
 * NES_CLOBBER_A/X/Y, NES_CLOBBER_FLAGS, NES_CLOBBER_MEMORY,
 * NES_ASM_BANK_EFFECT, NES_ASM_CALL(function), and NES_ASM_STACK(bytes).
 */

void nes_init(void);
void nes_wait_vblank(void);
void nes_wait_frame(void);

#endif
