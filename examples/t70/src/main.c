#include <nes.h>
#include <collision.h>
#include <input.h>
#include <metasprite.h>
#include <nametable.h>
#include <random.h>
#include <update.h>

/*
 * T-70 playable slice (T-M2): one stage from a PRG-ROM const table, a player
 * tank with four facing tile sets, a PRNG-patrolling enemy tank, shell
 * firing with destructible bricks, and win/lose states.
 *
 * The stage is 16x15 cells of 16x16 pixels: 0 = ground, 1 = brick
 * (destructible), 2 = concrete (solid). Each cell maps to 2x2 background
 * tiles and 2x2 collision-grid entries. Brick destruction updates the
 * collision grid immediately and repaints the nametable through the vblank
 * update buffer.
 *
 * Rules: the player's shell destroys bricks and the enemy (win); touching
 * the enemy destroys the player (lose). The backdrop color announces the
 * outcome: green for a win, red for a loss. The PRNG seed is fixed, so a
 * given input script always replays the same battle.
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

/* Metasprite base tiles indexed by direction: up, down, left, right. */
const u8 facing_tiles[4] = {1u8, 9u8, 13u8, 5u8};

#define T70_TILE_SHELL 17u8
#define T70_TILE_BRICK 18u8
#define T70_TILE_CONCRETE 19u8

#define T70_STATE_PLAYING 0u8
#define T70_STATE_WON 1u8
#define T70_STATE_LOST 2u8

static u8 game_state;
static u8 tank_x;
static u8 tank_y;
static u8 tank_dir; /* 0 up, 1 down, 2 left, 3 right */
static u8 shell_x;
static u8 shell_y;
static u8 shell_dir;
static u8 shell_active;
static u8 enemy_x;
static u8 enemy_y;
static u8 enemy_dir;
static u8 enemy_alive;

static u8 inside_box(u8 point, u8 origin) {
    return point >= origin && (u8)(point - origin) < 16u8;
}

static u8 boxes_touch(u8 ax, u8 ay, u8 bx, u8 by) {
    u8 dx = ax - bx;
    u8 dy = ay - by;
    if (ax < bx) {
        dx = bx - ax;
    }
    if (ay < by) {
        dy = by - ay;
    }
    return dx < 16u8 && dy < 16u8;
}

static void finish_game(u8 state, u8 backdrop) {
    game_state = state;
    nes_update_queue(0x3F00u16, backdrop);
}

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

static void update_enemy(void) {
    u8 new_x;
    u8 new_y;
    if (enemy_alive == 0u8) {
        return;
    }
    new_x = enemy_x;
    new_y = enemy_y;
    if (enemy_dir == 3u8) {
        new_x = enemy_x + 1u8;
    } else if (enemy_dir == 2u8) {
        new_x = enemy_x - 1u8;
    } else if (enemy_dir == 1u8) {
        new_y = enemy_y + 1u8;
    } else {
        new_y = enemy_y - 1u8;
    }
    if (nes_collision_box(new_x, new_y, 16u8, 16u8) == 0u8) {
        enemy_x = new_x;
        enemy_y = new_y;
    } else {
        enemy_dir = nes_rand8() & 3u8;
    }
    if (boxes_touch(tank_x, tank_y, enemy_x, enemy_y)) {
        finish_game(T70_STATE_LOST, 0x06u8);
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
    if (enemy_alive != 0u8 && inside_box(shell_x, enemy_x) && inside_box(shell_y, enemy_y)) {
        enemy_alive = 0u8;
        shell_active = 0u8;
        finish_game(T70_STATE_WON, 0x1Au8);
        return;
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
    if (game_state == T70_STATE_LOST) {
        nes_metasprite_hide(0u8);
    } else {
        nes_metasprite_draw(0u8, tank_x, tank_y, facing_tiles[tank_dir], 0u8);
    }
    if (enemy_alive != 0u8) {
        nes_metasprite_draw(8u8, enemy_x, enemy_y, facing_tiles[enemy_dir], 1u8);
    } else {
        nes_metasprite_hide(8u8);
    }
    if (shell_active != 0u8) {
        nes_set_sprite_tile(4u8, T70_TILE_SHELL);
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
                cell_tile = T70_TILE_CONCRETE;
                if (material == 1u8) {
                    cell_tile = T70_TILE_BRICK;
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
    nes_set_palette_color(17u8, 0x08u8); /* player tracks: dark olive */
    nes_set_palette_color(18u8, 0x1Au8); /* player body: green */
    nes_set_palette_color(19u8, 0x30u8); /* player cannon: white */
    nes_set_palette_color(21u8, 0x07u8); /* enemy tracks: dark brown */
    nes_set_palette_color(22u8, 0x10u8); /* enemy body: gray */
    nes_set_palette_color(23u8, 0x27u8); /* enemy cannon: tan */
}

NES_MAIN int main(void) {
    load_palettes();
    load_stage();
    game_state = T70_STATE_PLAYING;
    tank_x = 32u8;
    tank_y = 112u8;
    tank_dir = 3u8;
    enemy_x = 208u8;
    enemy_y = 112u8;
    enemy_dir = 2u8;
    enemy_alive = 1u8;
    nes_srand(0x1234u16);
    nes_update_reset();
    nes_set_ppu_address(0x0000u16);
    nes_enable_rendering();
    while (true) {
        nes_wait_frame();
        nes_update_flush();
        nes_set_ppu_address(0x0000u16);
        nes_oam_dma();
        nes_input_poll();
        if (game_state == T70_STATE_PLAYING) {
            update_tank();
            update_shell();
            update_enemy();
        }
        draw();
    }
}
