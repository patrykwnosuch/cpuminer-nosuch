/*
 * Argon2 reference source code package - reference C implementations
 *
 * Copyright 2015
 * Daniel Dinu, Dmitry Khovratovich, Jean-Philippe Aumasson, and Samuel Neves
 *
 * You may use this work under the terms of a Creative Commons CC0 1.0
 * License/Waiver or the Apache Public License 2.0, at your option. The terms of
 * these licenses can be found at:
 *
 * - CC0 1.0 Universal : http://creativecommons.org/publicdomain/zero/1.0
 * - Apache 2.0        : http://www.apache.org/licenses/LICENSE-2.0
 *
 * You should have received a copy of both of these licenses along with this
 * software. If not, they may be obtained at the above URLs.
 */

#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include "argon2.h"
#include "core.h"

#include "../blake2/blake2.h"
#include "../blake2/blamka-round-opt.h"

/*
 * Function fills a new memory block and optionally XORs the old block over the new one.
 * Memory must be initialized.
 * @param state Pointer to the just produced block. Content will be updated(!)
 * @param ref_block Pointer to the reference block
 * @param next_block Pointer to the block to be XORed over. May coincide with @ref_block
 * @param with_xor Whether to XOR into the new block (1) or just overwrite (0)
 * @pre all block pointers must be valid
 */

#if defined(__AVX512F__)

static void fill_block(__m512i *state, const block *ref_block,
                       block *next_block, int with_xor) {
    __m512i block_XY[ARGON2_512BIT_WORDS_IN_BLOCK];
    unsigned int i;
    if (with_xor) {
        for (i = 0; i < ARGON2_512BIT_WORDS_IN_BLOCK; i++) {
            state[i] = _mm512_xor_si512(
                state[i], _mm512_loadu_si512((const __m512i *)ref_block->v + i));
            block_XY[i] = _mm512_xor_si512(
                state[i], _mm512_loadu_si512((const __m512i *)next_block->v + i));
        }
    } else {
        for (i = 0; i < ARGON2_512BIT_WORDS_IN_BLOCK; i++) {
            block_XY[i] = state[i] = _mm512_xor_si512(
                state[i], _mm512_loadu_si512((const __m512i *)ref_block->v + i));
        }
    }

    BLAKE2_ROUND_1( state[ 0], state[ 1], state[ 2], state[ 3],
                    state[ 4], state[ 5], state[ 6], state[ 7] );
    BLAKE2_ROUND_1( state[ 8], state[ 9], state[10], state[11],
                    state[12], state[13], state[14], state[15] );

    BLAKE2_ROUND_2( state[ 0], state[ 2], state[ 4], state[ 6],
                    state[ 8], state[10], state[12], state[14] );
    BLAKE2_ROUND_2( state[ 1], state[ 3], state[ 5], state[ 7],
                    state[ 9], state[11], state[13], state[15] );

    for (i = 0; i < ARGON2_512BIT_WORDS_IN_BLOCK; i++) {
        state[i] = _mm512_xor_si512(state[i], block_XY[i]);
        _mm512_storeu_si512((__m512i *)next_block->v + i, state[i]);
    }
}

#elif defined(__AVX2__)

static void fill_block(__m256i *state, const block *ref_block,
                       block *next_block, int with_xor) {
    __m256i block_XY[ARGON2_HWORDS_IN_BLOCK];
    unsigned int i;

    if (with_xor) {
        for (i = 0; i < ARGON2_HWORDS_IN_BLOCK; i++) {
            state[i] = _mm256_xor_si256(
                state[i], _mm256_loadu_si256((const __m256i *)ref_block->v + i));
            block_XY[i] = _mm256_xor_si256(
                state[i], _mm256_loadu_si256((const __m256i *)next_block->v + i));
        }
    } else {
        for (i = 0; i < ARGON2_HWORDS_IN_BLOCK; i++) {
            block_XY[i] = state[i] = _mm256_xor_si256(
                state[i], _mm256_loadu_si256((const __m256i *)ref_block->v + i));
        }
    }

    BLAKE2_ROUND_1( state[ 0], state[ 4], state[ 1], state[ 5],
                    state[ 2], state[ 6], state[ 3], state[ 7] );
    BLAKE2_ROUND_1( state[ 8], state[12], state[ 9], state[13],
                    state[10], state[14], state[11], state[15] );
    BLAKE2_ROUND_1( state[16], state[20], state[17], state[21],
                    state[18], state[22], state[19], state[23] );
    BLAKE2_ROUND_1( state[24], state[28], state[25], state[29],
                    state[26], state[30], state[27], state[31] );

    BLAKE2_ROUND_2( state[ 0], state[ 4], state[ 8], state[12],
                    state[16], state[20], state[24], state[28] );
    BLAKE2_ROUND_2( state[ 1], state[ 5], state[ 9], state[13],
                    state[17], state[21], state[25], state[29] );
    BLAKE2_ROUND_2( state[ 2], state[ 6], state[10], state[14],
                    state[18], state[22], state[26], state[30] );
    BLAKE2_ROUND_2( state[ 3], state[ 7], state[11], state[15],
                    state[19], state[23], state[27], state[31] );

    for (i = 0; i < ARGON2_HWORDS_IN_BLOCK; i++) {
        state[i] = _mm256_xor_si256(state[i], block_XY[i]);
        _mm256_storeu_si256((__m256i *)next_block->v + i, state[i]);
    }
}

#else  // SSE2

static void fill_block(__m128i *state, const block *ref_block,
                       block *next_block, int with_xor) {
    __m128i block_XY[ARGON2_OWORDS_IN_BLOCK];
    unsigned int i;

    if (with_xor) {
        for (i = 0; i < ARGON2_OWORDS_IN_BLOCK; i++) {
            state[i] = _mm_xor_si128(
                state[i], _mm_loadu_si128((const __m128i *)ref_block->v + i));
            block_XY[i] = _mm_xor_si128(
                state[i], _mm_loadu_si128((const __m128i *)next_block->v + i));
        }
    } else {
        for (i = 0; i < ARGON2_OWORDS_IN_BLOCK; i++) {
            block_XY[i] = state[i] = _mm_xor_si128(
                state[i], _mm_loadu_si128((const __m128i *)ref_block->v + i));
        }
    }

    BLAKE2_ROUND( state[ 0], state[ 1], state[ 2], state[ 3],
                  state[ 4], state[ 5], state[ 6], state[ 7] );
    BLAKE2_ROUND( state[ 8], state[ 9], state[10], state[11], 
                  state[12], state[13], state[14], state[15] );
    BLAKE2_ROUND( state[16], state[17], state[18], state[19], 
                  state[20], state[21], state[22], state[23] );
    BLAKE2_ROUND( state[24], state[25], state[26], state[27], 
                  state[28], state[29], state[30], state[31] );
    BLAKE2_ROUND( state[32], state[33], state[34], state[35], 
                  state[36], state[37], state[38], state[39] );
    BLAKE2_ROUND( state[40], state[41], state[42], state[43], 
                  state[44], state[45], state[46], state[47] );
    BLAKE2_ROUND( state[48], state[49], state[50], state[51], 
                  state[52], state[53], state[54], state[55] );
    BLAKE2_ROUND( state[56], state[57], state[58], state[59], 
                  state[60], state[61], state[62], state[63] );

    BLAKE2_ROUND( state[ 0], state[ 8], state[16], state[24], 
                  state[32], state[40], state[48], state[56] );
    BLAKE2_ROUND( state[ 1], state[ 9], state[17], state[25],  
                  state[33], state[41], state[49], state[57] );
    BLAKE2_ROUND( state[ 2], state[10], state[18], state[26],  
                  state[34], state[42], state[50], state[58] );
    BLAKE2_ROUND( state[ 3], state[11], state[19], state[27],  
                  state[35], state[43], state[51], state[59] );
    BLAKE2_ROUND( state[ 4], state[12], state[20], state[28],  
                  state[36], state[44], state[52], state[60] );
    BLAKE2_ROUND( state[ 5], state[13], state[21], state[29],  
                  state[37], state[45], state[53], state[61] );
    BLAKE2_ROUND( state[ 6], state[14], state[22], state[30],  
                  state[38], state[46], state[54], state[62] );
    BLAKE2_ROUND( state[ 7], state[15], state[23], state[31],  
                  state[39], state[47], state[55], state[63] );

    for (i = 0; i < ARGON2_OWORDS_IN_BLOCK; i++) {
        state[i] = _mm_xor_si128(state[i], block_XY[i]);
        _mm_storeu_si128((__m128i *)next_block->v + i, state[i]);
    }
}

#endif

#if 0
static void next_addresses(block *address_block, block *input_block) {
    /*Temporary zero-initialized blocks*/
#if defined(__AVX512F__)
    __m512i zero_block[ARGON2_512BIT_WORDS_IN_BLOCK];
    __m512i zero2_block[ARGON2_512BIT_WORDS_IN_BLOCK];
#elif defined(__AVX2__)
    __m256i zero_block[ARGON2_HWORDS_IN_BLOCK];
    __m256i zero2_block[ARGON2_HWORDS_IN_BLOCK];
#else
    __m128i zero_block[ARGON2_OWORDS_IN_BLOCK];
    __m128i zero2_block[ARGON2_OWORDS_IN_BLOCK];
#endif

    input_block->v[6]++;
    fill_block(zero_block, input_block, address_block, 0);
    fill_block(zero2_block, address_block, address_block, 0);
}
#endif

void fill_segment(const argon2_instance_t *instance,
                  argon2_position_t position) {
    block *ref_block = NULL, *curr_block = NULL;
//    block address_block, input_block;
    uint64_t pseudo_rand, ref_index, ref_lane;
    uint32_t prev_offset, curr_offset;
    uint32_t starting_index, i;
#if defined(__AVX512F__)
    __m512i state[ARGON2_512BIT_WORDS_IN_BLOCK];
#elif defined(__AVX2__)
    __m256i state[ARGON2_HWORDS_IN_BLOCK];
#else
    __m128i state[ARGON2_OWORDS_IN_BLOCK];
#endif
//    int data_independent_addressing;

    starting_index = 0;

    if ((0 == position.pass) && (0 == position.slice))
        starting_index = 2;

    curr_offset = position.lane * instance->lane_length + position.slice * instance->segment_length + starting_index;

    if (0 == curr_offset % instance->lane_length)
        prev_offset = curr_offset + instance->lane_length - 1;
    else
        prev_offset = curr_offset - 1;

    memcpy(state, ((instance->memory + prev_offset)->v), ARGON2_BLOCK_SIZE);

    for (i = starting_index; i < instance->segment_length; ++i, ++curr_offset, ++prev_offset) {

        if (curr_offset % instance->lane_length == 1)
            prev_offset = curr_offset - 1;

        pseudo_rand = instance->memory[prev_offset].v[0];

        ref_lane = ((pseudo_rand >> 32)) % instance->lanes;

        if ((position.pass == 0) && (position.slice == 0))
            ref_lane = position.lane;

        position.index = i;
        ref_index = index_alpha(instance, &position, pseudo_rand & 0xFFFFFFFF, ref_lane == position.lane);
        ref_block = instance->memory + instance->lane_length * ref_lane + ref_index;
        curr_block = instance->memory + curr_offset;

        if(0 == position.pass) {
          fill_block(state, ref_block, curr_block, 0);
        } else {
          fill_block(state, ref_block, curr_block, 1);
        }
     }
}
