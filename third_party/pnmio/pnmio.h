/*
 * pnmio.h
 * I/O interface to the Portable Any Map (PNM) image format.
 * Version 0.4, Release 2025-May-07.
 *
 * Copyright (C) 2002-2025 Cosmin Truta.
 *
 * Use, modification and distribution are subject
 * to the Boost Software License, Version 1.0.
 * See the accompanying file LICENSE_BSL_1_0.txt
 * or visit https://www.boost.org/LICENSE_1_0.txt
 *
 * SPDX-License-Identifier: BSL-1.0
 */


#ifndef PNMIO_H_
#define PNMIO_H_

#include <stddef.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif


/*
 * PNM format codes.
 */
enum
{
   PNM_P1 = 1,  /* plain PBM */
   PNM_P2 = 2,  /* plain PGM */
   PNM_P3 = 3,  /* plain PPM */
   PNM_P4 = 4,  /* raw PBM */
   PNM_P5 = 5,  /* raw PGM */
   PNM_P6 = 6,  /* raw PPM */
   PNM_P7 = 7   /* PAM (only partially implemented) */
};


/*
 * PNM info structure.
 */
typedef struct pnm_struct
{
   unsigned int format;
   unsigned int depth;
   unsigned int width;
   unsigned int height;
   unsigned int maxval;
} pnm_struct;


/*
 * PNM input functions.
 */
int pnm_fget_header(pnm_struct *pnm_ptr, FILE *stream);
int pnm_fget_values(const pnm_struct *pnm_ptr,
                    unsigned int *sample_values,
                    unsigned int num_rows,
                    FILE *stream);
int pnm_fget_bytes(const pnm_struct *pnm_ptr,
                   unsigned char *sample_bytes,
                   size_t sample_size,
                   unsigned int num_rows,
                   FILE *stream);


/*
 * PNM output functions.
 */
int pnm_fput_header(const pnm_struct *pnm_ptr, FILE *stream);
int pnm_fput_values(const pnm_struct *pnm_ptr,
                    const unsigned int *sample_values,
                    unsigned int num_rows,
                    FILE *stream);
int pnm_fput_bytes(const pnm_struct *pnm_ptr,
                   const unsigned char *sample_bytes,
                   size_t sample_size,
                   unsigned int num_rows,
                   FILE *stream);


/*
 * PNM utility functions.
 */
int pnm_is_valid(const pnm_struct *pnm_ptr);
size_t pnm_raw_sample_size(const pnm_struct *pnm_ptr);
size_t pnm_mem_size(const pnm_struct *pnm_ptr,
                    size_t sample_size,
                    unsigned int num_rows);


/*
 * PNM limits.
 */
#define PNM_BYTE_MAX 0xffU
#define PNM_VALUE_MAX 0xffffffffU
#define PNM_SIZE_MAX (~0U)
#if PNM_SIZE_MAX < 0xffffffffUL
#error This software requires a 32-bit machine (or bigger).
#endif


#ifdef __cplusplus
}  /* extern "C" */
#endif

#endif  /* PNMIO_H_ */
