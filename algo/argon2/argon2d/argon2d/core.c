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

/*For memory wiping*/
#ifdef _MSC_VER
#include <windows.h>
#include <winbase.h> /* For SecureZeroMemory */
#endif
#if defined __STDC_LIB_EXT1__
#define __STDC_WANT_LIB_EXT1__ 1
#endif
#define VC_GE_2005(version) (version >= 1400)

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core.h"
#include "thread.h"
#include "../blake2/blake2.h"
#include "../blake2/blake2-impl.h"

#ifdef GENKAT
#include "genkat.h"
#endif

#if defined(__clang__)
#if __has_attribute(optnone)
#define NOT_OPTIMIZED __attribute__((optnone))
#endif
#elif defined(__GNUC__)
#define GCC_VERSION                                                            \
    (__GNUC__ * 10000 + __GNUC_MINOR__ * 100 + __GNUC_PATCHLEVEL__)
#if GCC_VERSION >= 40400
#define NOT_OPTIMIZED __attribute__((optimize("O0")))
#endif
#endif
#ifndef NOT_OPTIMIZED
#define NOT_OPTIMIZED
#endif

/***************Instance and Position constructors**********/
void init_block_value(block *b, uint8_t in) { memset(b->v, in, sizeof(b->v)); }

void copy_block(block *dst, const block *src) {
    memcpy(dst->v, src->v, sizeof(uint64_t) * ARGON2_QWORDS_IN_BLOCK);
}

void xor_block(block *dst, const block *src) {
    int i;
    for (i = 0; i < ARGON2_QWORDS_IN_BLOCK; ++i) {
        dst->v[i] ^= src->v[i];
    }
}

static void load_block(block *dst, const void *input) {
    unsigned i;
    for (i = 0; i < ARGON2_QWORDS_IN_BLOCK; ++i) {
        dst->v[i] = load64((const uint8_t *)input + i * sizeof(dst->v[i]));
    }
}

static void store_block(void *output, const block *src) {
    unsigned i;
    for (i = 0; i < ARGON2_QWORDS_IN_BLOCK; ++i) {
        store64((uint8_t *)output + i * sizeof(src->v[i]), src->v[i]);
    }
}

/***************Memory functions*****************/

int allocate_memory(const argon2_context *context, uint8_t **memory, size_t num, size_t size) {
    if (context->allocate_cbk) {
        (context->allocate_cbk)(memory, num*size);
	return ARGON2_OK;
    }
    *memory = malloc(num*size);
    return ARGON2_OK;
}

void free_memory(const argon2_context *context, uint8_t *memory,
                 size_t num, size_t size) {
    size_t memory_size = num*size;
    clear_internal_memory(memory, memory_size);
    if (context->free_cbk) {
        (context->free_cbk)(memory, memory_size);
    } else {
        free(memory);
    }
}

void NOT_OPTIMIZED secure_wipe_memory(void *v, size_t n) {
#if defined(_MSC_VER) && VC_GE_2005(_MSC_VER)
    SecureZeroMemory(v, n);
#elif defined memset_s
    memset_s(v, n, 0, n);
#elif defined(__OpenBSD__)
    explicit_bzero(v, n);
#else
    static void *(*const volatile memset_sec)(void *, int, size_t) = &memset;
    memset_sec(v, 0, n);
#endif
}

/* Memory clear flag defaults to true. */
int FLAG_clear_internal_memory = 0;
void clear_internal_memory(void *v, size_t n) {
  if (FLAG_clear_internal_memory && v) {
    secure_wipe_memory(v, n);
  }
}

void finalize(const argon2_context *context, argon2_instance_t *instance) {
    if (context != NULL && instance != NULL) {
        block blockhash;
        uint32_t l;

        copy_block(&blockhash, instance->memory + instance->lane_length - 1);

        /* XOR the last blocks */
        for (l = 1; l < instance->lanes; ++l) {
            uint32_t last_block_in_lane =
                l * instance->lane_length + (instance->lane_length - 1);
            xor_block(&blockhash, instance->memory + last_block_in_lane);
        }

        /* Hash the result */
        {
            uint8_t blockhash_bytes[ARGON2_BLOCK_SIZE];
            store_block(blockhash_bytes, &blockhash);
            blake2b_long(context->out, context->outlen, blockhash_bytes,
                         ARGON2_BLOCK_SIZE);
            /* clear blockhash and blockhash_bytes */
            clear_internal_memory(blockhash.v, ARGON2_BLOCK_SIZE);
            clear_internal_memory(blockhash_bytes, ARGON2_BLOCK_SIZE);
        }

        free_memory(context, (uint8_t *)instance->memory,
                    instance->memory_blocks, sizeof(block));
    }
}

uint32_t index_alpha(const argon2_instance_t *instance,
                     const argon2_position_t *position, uint32_t pseudo_rand,
                     int same_lane) {
    /*
     * Pass 0:
     *      This lane : all already finished segments plus already constructed
     * blocks in this segment
     *      Other lanes : all already finished segments
     * Pass 1+:
     *      This lane : (SYNC_POINTS - 1) last segments plus already constructed
     * blocks in this segment
     *      Other lanes : (SYNC_POINTS - 1) last segments
     */
    uint32_t reference_area_size;
    uint64_t relative_position;
    uint32_t start_position, absolute_position;

    if (0 == position->pass) {
        /* First pass */
        if (0 == position->slice) {
            /* First slice */
            reference_area_size =
                position->index - 1; /* all but the previous */
        } else {
            if (same_lane) {
                /* The same lane => add current segment */
                reference_area_size =
                    position->slice * instance->segment_length +
                    position->index - 1;
            } else {
                reference_area_size =
                    position->slice * instance->segment_length +
                    ((position->index == 0) ? (-1) : 0);
            }
        }
    } else {
        /* Second pass */
        if (same_lane) {
            reference_area_size = instance->lane_length -
                                  instance->segment_length + position->index -
                                  1;
        } else {
            reference_area_size = instance->lane_length -
                                  instance->segment_length +
                                  ((position->index == 0) ? (-1) : 0);
        }
    }

    /* 1.2.4. Mapping pseudo_rand to 0..<reference_area_size-1> and produce
     * relative position */
    relative_position = pseudo_rand;
    relative_position = relative_position * relative_position >> 32;
    relative_position = reference_area_size - 1 -
                        (reference_area_size * relative_position >> 32);

    /* 1.2.5 Computing starting position */
    start_position = 0;

    if (0 != position->pass) {
        start_position = (position->slice == ARGON2_SYNC_POINTS - 1)
                             ? 0
                             : (position->slice + 1) * instance->segment_length;
    }

    /* 1.2.6. Computing absolute position */
    absolute_position = (start_position + relative_position) %
                        instance->lane_length; /* absolute position */
    return absolute_position;
}

/* Single-threaded version for p=1 case */
static int fill_memory_blocks_st(argon2_instance_t *instance) {
    uint32_t r, s, l;

    for (r = 0; r < instance->passes; ++r) {
        for (s = 0; s < ARGON2_SYNC_POINTS; ++s) {
            for (l = 0; l < instance->lanes; ++l) {
                argon2_position_t position = {r, l, (uint8_t)s, 0};
                fill_segment(instance, position);
            }
        }
#ifdef GENKAT
        internal_kat(instance, r); /* Print all memory blocks */
#endif
    }
    return ARGON2_OK;
}

#if !defined(ARGON2_NO_THREADS)

#ifdef _WIN32
static unsigned __stdcall fill_segment_thr(void *thread_data)
#else
static void *fill_segment_thr(void *thread_data)
#endif
{
    argon2_thread_data *my_data = thread_data;
    fill_segment(my_data->instance_ptr, my_data->pos);
    argon2_thread_exit();
    return 0;
}

/* Multi-threaded version for p > 1 case */
static int fill_memory_blocks_mt(argon2_instance_t *instance) {
    uint32_t r, s;
    argon2_thread_handle_t *thread = NULL;
    argon2_thread_data *thr_data = NULL;
    int rc = ARGON2_OK;

    /* 1. Allocating space for threads */
    thread = calloc(instance->lanes, sizeof(argon2_thread_handle_t));
    if (thread == NULL) {
        rc = ARGON2_MEMORY_ALLOCATION_ERROR;
        goto fail;
    }

    thr_data = calloc(instance->lanes, sizeof(argon2_thread_data));
    if (thr_data == NULL) {
        rc = ARGON2_MEMORY_ALLOCATION_ERROR;
        goto fail;
    }

    for (r = 0; r < instance->passes; ++r) {
        for (s = 0; s < ARGON2_SYNC_POINTS; ++s) {
            uint32_t l;

            /* 2. Calling threads */
            for (l = 0; l < instance->lanes; ++l) {
                argon2_position_t position;

                /* 2.1 Join a thread if limit is exceeded */
                if (l >= instance->threads) {
                    if (argon2_thread_join(thread[l - instance->threads])) {
                        rc = ARGON2_THREAD_FAIL;
                        goto fail;
                    }
                }

                /* 2.2 Create thread */
                position.pass = r;
                position.lane = l;
                position.slice = (uint8_t)s;
                position.index = 0;
                thr_data[l].instance_ptr =
                    instance; /* preparing the thread input */
                memcpy(&(thr_data[l].pos), &position,
                       sizeof(argon2_position_t));
                if (argon2_thread_create(&thread[l], &fill_segment_thr,
                                         (void *)&thr_data[l])) {
                    rc = ARGON2_THREAD_FAIL;
                    goto fail;
                }

                /* fill_segment(instance, position); */
                /*Non-thread equivalent of the lines above */
            }

            /* 3. Joining remaining threads */
            for (l = instance->lanes - instance->threads; l < instance->lanes;
                 ++l) {
                if (argon2_thread_join(thread[l])) {
                    rc = ARGON2_THREAD_FAIL;
                    goto fail;
                }
            }
        }

#ifdef GENKAT
        internal_kat(instance, r); /* Print all memory blocks */
#endif
    }

fail:
    if (thread != NULL) {
        free(thread);
    }
    if (thr_data != NULL) {
        free(thr_data);
    }
    return rc;
}

#endif /* ARGON2_NO_THREADS */

int fill_memory_blocks(argon2_instance_t *instance) {
    return instance->threads == 1 ? fill_memory_blocks_st(instance) : fill_memory_blocks_mt(instance);
}

int validate_inputs(const argon2_context *context) {
    return ARGON2_OK;
}

int initialize(argon2_instance_t *instance, argon2_context *context) {

    uint32_t l;
    uint8_t blockhash_bytes[ARGON2_BLOCK_SIZE];
    uint8_t blockhash[ARGON2_PREHASH_SEED_LENGTH];
    int result = ARGON2_OK;
    instance->context_ptr = context;
    allocate_memory(context, (uint8_t **)&(instance->memory),instance->memory_blocks, sizeof(block));
    blake2b_state BlakeHash;
    uint8_t value[sizeof(uint32_t)];
    blake2b_init(&BlakeHash, ARGON2_PREHASH_DIGEST_LENGTH);
    store32(&value, context->lanes);
    blake2b_update(&BlakeHash, (const uint8_t *)&value, sizeof(value));
    store32(&value, context->outlen);
    blake2b_update(&BlakeHash, (const uint8_t *)&value, sizeof(value));
    store32(&value, context->m_cost);
    blake2b_update(&BlakeHash, (const uint8_t *)&value, sizeof(value));
    store32(&value, context->t_cost);
    blake2b_update(&BlakeHash, (const uint8_t *)&value, sizeof(value));
    store32(&value, context->version);
    blake2b_update(&BlakeHash, (const uint8_t *)&value, sizeof(value));
    store32(&value, (uint32_t)instance->type);
    blake2b_update(&BlakeHash, (const uint8_t *)&value, sizeof(value));
    store32(&value, context->pwdlen);

    // combine every two _update rounds
    uint8_t contextcombine[68];
    memcpy(contextcombine,(const uint8_t *)&value,4);
    memcpy(contextcombine+4,(const uint8_t *)context->pwd,40);
    blake2b_update(&BlakeHash, (const uint8_t *)contextcombine, 44);
    store32(&value, context->saltlen);
    memcpy(contextcombine,(const uint8_t *)&value,4);
    memcpy(contextcombine+4,(const uint8_t *)context->salt,40);
    blake2b_update(&BlakeHash, (const uint8_t *)contextcombine, 44);
    store32(&value, context->secretlen);
    memcpy(contextcombine,(const uint8_t *)&value,4);
    memcpy(contextcombine+4,(const uint8_t *)context->secret,64);
    blake2b_update(&BlakeHash, (const uint8_t *)contextcombine, 68);

    // this one is slower if combined
    store32(&value, context->adlen);
    blake2b_update(&BlakeHash, (const uint8_t *)&value, sizeof(value));
    blake2b_update(&BlakeHash, (const uint8_t *)context->ad, context->adlen);

    blake2b_final(&BlakeHash, blockhash, ARGON2_PREHASH_DIGEST_LENGTH);
    store32(blockhash + ARGON2_PREHASH_DIGEST_LENGTH, 0);
    store32(blockhash + ARGON2_PREHASH_DIGEST_LENGTH + 4, 0);
    blake2b_long(blockhash_bytes, ARGON2_BLOCK_SIZE, blockhash, ARGON2_PREHASH_SEED_LENGTH);
    load_block(&instance->memory[0 * instance->lane_length + 0], blockhash_bytes);
    store32(blockhash + ARGON2_PREHASH_DIGEST_LENGTH, 1);
    blake2b_long(blockhash_bytes, ARGON2_BLOCK_SIZE, blockhash, ARGON2_PREHASH_SEED_LENGTH);
    load_block(&instance->memory[0 * instance->lane_length + 1], blockhash_bytes);
    store32(blockhash + ARGON2_PREHASH_DIGEST_LENGTH, 0);
    store32(blockhash + ARGON2_PREHASH_DIGEST_LENGTH + 4, 1);
    blake2b_long(blockhash_bytes, ARGON2_BLOCK_SIZE, blockhash, ARGON2_PREHASH_SEED_LENGTH);
    load_block(&instance->memory[1 * instance->lane_length + 0], blockhash_bytes);
    store32(blockhash + ARGON2_PREHASH_DIGEST_LENGTH, 1);
    blake2b_long(blockhash_bytes, ARGON2_BLOCK_SIZE, blockhash, ARGON2_PREHASH_SEED_LENGTH);
    load_block(&instance->memory[1 * instance->lane_length + 1], blockhash_bytes);

    return ARGON2_OK;
}
