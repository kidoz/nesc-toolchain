#include <nes.h>
#include <collision.h>
#include <input.h>
#include <metasprite.h>
#include <nametable.h>
#include <update.h>

/*
 * T-70 first playable slice (T-M1): one stage grid rendered from a PRG-ROM
 * const table, a player tank driven by controller 1, collision-blocked
 * movement, and shell firing with destructible brick cells.
 *
 * The stage is 16x15 cells of 16x16 pixels: 0 = ground, 1 = brick
 * (destructible), 2 = concrete (solid). Each cell maps to 2x2 background
 * tiles and 2x2 collision-grid entries. Brick destruction updates the
 * collision grid immediately and repaints the nametable through the vblank
 * update buffer. This slice uses one tank shape for all four facings.
 */

const u8 stage_cells[240] = {
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
    2, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 2,
    2, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 2,
    2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
    2, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 2, 2, 0, 2,
    2, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 2, 2, 0, 2,
    2, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
    2, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
    2, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
    2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
    2, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 2,
    2, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 2,
    2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
};

static u8 tank_x;
static u8 tank_y;
static u8 tank_dir; /* 0 up, 1 down, 2 left, 3 right */
static u8 shell_x;
static u8 shell_y;
static u8 shell_dir;
static u8 shell_active;

static void update_tank(void) {
    u8 held = nes_input_held(0u8);
    u8 new_x = tank_x;
    u8 new_y = tank_y;
    if ((held & NES_BUTTON_RIGHT) != 0u8) {
        new_x = tank_x + 2u8;
        tank_dir = 3u8;
    } else if ((held & NES_BUTTON_LEFT) != 0u8) {
        new_x = tank_x - 2u8;
        tank_dir = 2u8;
    } else if ((held & NES_BUTTON_DOWN) != 0u8) {
        new_y = tank_y + 2u8;
        tank_dir = 1u8;
    } else if ((held & NES_BUTTON_UP) != 0u8) {
        new_y = tank_y - 2u8;
        tank_dir = 0u8;
    }
    if (nes_collision_box(new_x, new_y, 16u8, 16u8) == 0u8) {
        tank_x = new_x;
        tank_y = new_y;
    }
    if ((nes_input_pressed(0u8) & NES_BUTTON_A) != 0u8 && shell_active == 0u8) {
        shell_active = 1u8;
        shell_dir = tank_dir;
        shell_x = tank_x + 7u8;
        shell_y = tank_y + 7u8;
    }
}

static void destroy_brick_cell(u8 cell_x, u8 cell_y) {
    u8 tile_x = cell_x << 1u8;
    u8 tile_y = cell_y << 1u8;
    nes_collision_set(tile_x, tile_y, 0u8);
    nes_collision_set(tile_x + 1u8, tile_y, 0u8);
    nes_collision_set(tile_x, tile_y + 1u8, 0u8);
    nes_collision_set(tile_x + 1u8, tile_y + 1u8, 0u8);
    nes_update_queue(nes_nametable_address(tile_x, tile_y), 0u8);
    nes_update_queue(nes_nametable_address(tile_x + 1u8, tile_y), 0u8);
    nes_update_queue(nes_nametable_address(tile_x, tile_y + 1u8), 0u8);
    nes_update_queue(nes_nametable_address(tile_x + 1u8, tile_y + 1u8), 0u8);
}

static void update_shell(void) {
    u8 material;
    if (shell_active == 0u8) {
        return;
    }
    if (shell_dir == 3u8) {
        shell_x = shell_x + 4u8;
    } else if (shell_dir == 2u8) {
        shell_x = shell_x - 4u8;
    } else if (shell_dir == 1u8) {
        shell_y = shell_y + 4u8;
    } else {
        shell_y = shell_y - 4u8;
    }
    material = nes_collision_at(shell_x, shell_y);
    if (material == 1u8) {
        destroy_brick_cell(shell_x >> 4u8, shell_y >> 4u8);
        shell_active = 0u8;
    } else if (material != 0u8) {
        shell_active = 0u8;
    }
}

static void draw(void) {
    nes_metasprite_draw(0u8, tank_x, tank_y, 1u8, 0u8);
    if (shell_active != 0u8) {
        nes_set_sprite_tile(4u8, 7u8);
        nes_set_sprite_attributes(4u8, 0u8);
        nes_set_sprite_position(4u8, shell_x - 4u8, shell_y - 4u8);
    } else {
        nes_set_sprite_position(4u8, 0u8, 0xFFu8);
    }
}

static void load_stage(void) {
    u8 cell_x;
    u8 cell_y;
    u8 material;
    u8 cell_tile;
    u8 tile_x;
    u8 tile_y;
    nes_collision_clear(0u8);
    for (cell_y = 0u8; cell_y < 15u8; cell_y++) {
        for (cell_x = 0u8; cell_x < 16u8; cell_x++) {
            material = stage_cells[(u8)((cell_y << 4u8) + cell_x)];
            if (material != 0u8) {
                cell_tile = 6u8;
                if (material == 1u8) {
                    cell_tile = 5u8;
                }
                tile_x = cell_x << 1u8;
                tile_y = cell_y << 1u8;
                nes_set_tile(tile_x, tile_y, cell_tile);
                nes_set_tile(tile_x + 1u8, tile_y, cell_tile);
                nes_set_tile(tile_x, tile_y + 1u8, cell_tile);
                nes_set_tile(tile_x + 1u8, tile_y + 1u8, cell_tile);
                nes_collision_set(tile_x, tile_y, material);
                nes_collision_set(tile_x + 1u8, tile_y, material);
                nes_collision_set(tile_x, tile_y + 1u8, material);
                nes_collision_set(tile_x + 1u8, tile_y + 1u8, material);
            }
        }
    }
}

static void load_palettes(void) {
    nes_set_palette_color(0u8, 0x0Fu8);  /* backdrop: black */
    nes_set_palette_color(1u8, 0x16u8);  /* brick: red */
    nes_set_palette_color(2u8, 0x00u8);  /* concrete: gray */
    nes_set_palette_color(3u8, 0x30u8);  /* concrete studs: white */
    nes_set_palette_color(17u8, 0x2Au8); /* tank detail: light green */
    nes_set_palette_color(18u8, 0x1Au8); /* tank body: green */
    nes_set_palette_color(19u8, 0x30u8); /* shell: white */
}

NES_MAIN int main(void) {
    load_palettes();
    load_stage();
    tank_x = 32u8;
    tank_y = 112u8;
    tank_dir = 3u8;
    nes_update_reset();
    nes_set_ppu_address(0x0000u16);
    nes_enable_rendering();
    while (true) {
        nes_wait_frame();
        nes_update_flush();
        nes_set_ppu_address(0x0000u16);
        nes_oam_dma();
        nes_input_poll();
        update_tank();
        update_shell();
        draw();
    }
}
