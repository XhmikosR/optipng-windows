/*
 * optim.c
 * The main PNG optimization engine.
 *
 * Copyright (C) 2001-2023 Cosmin Truta and the Contributing Authors.
 *
 * This software is distributed under the zlib license.
 * Please see the accompanying LICENSE file.
 */

#include "optipng.h"
#include "proginfo.h"

#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <opngreduc.h>
#include <png.h>
#include <pngxtern.h>
#include <pngxutil.h>
#include <zlib.h>

#include "bitset.h"
#include "ioutil.h"
#include "ratio.h"


/*
 * Exception handling setup.
 */
#include <cexcept.h>
typedef enum
{
    OPNG_STATUS_OK = 0,
    OPNG_STATUS_ERR_LIBPNG = -1,
    OPNG_STATUS_ERR_OPTIPNG = -2
} opng_status_t;
define_exception_type(opng_status_t);
struct exception_context the_exception_context[1];


/*
 * The optimization level presets.
 */
static const struct opng_preset_struct
{
    const char *compr_level;
    const char *mem_level;
    const char *strategy;
    const char *filter;
} k_presets[OPNG_OPTIM_LEVEL_MAX + 1] =
{
/*  { -zc    -zm    -zs   -f    }  */
    { "",    "",    "",   ""    },  /* -o0 */
    { "",    "",    "",   ""    },  /* -o1 */
    { "9",   "8",   "0-", "0,5" },  /* -o2 */
    { "9",   "8-9", "0-", "0,5" },  /* -o3 */
    { "9",   "8",   "0-", "0-"  },  /* -o4 */
    { "9",   "8-9", "0-", "0-"  },  /* -o5 */
    { "1-9", "8",   "0-", "0-"  },  /* -o6 */
    { "1-9", "8-9", "0-", "0-"  }   /* -o7 */
};

/*
 * The filter table.
 */
static const int k_filter_table[OPNG_FILTER_MAX + 1] =
{
    PNG_FILTER_NONE,   /* -f0 */
    PNG_FILTER_SUB,    /* -f1 */
    PNG_FILTER_UP,     /* -f2 */
    PNG_FILTER_AVG,    /* -f3 */
    PNG_FILTER_PAETH,  /* -f4 */
    PNG_ALL_FILTERS    /* -f5 */
};

/*
 * The chunks handled by OptiPNG.
 */
static const png_byte k_sig_PLTE[4] = { 0x50, 0x4c, 0x54, 0x45 };
static const png_byte k_sig_tRNS[4] = { 0x74, 0x52, 0x4e, 0x53 };
static const png_byte k_sig_IDAT[4] = { 0x49, 0x44, 0x41, 0x54 };
static const png_byte k_sig_IEND[4] = { 0x49, 0x45, 0x4e, 0x44 };
static const png_byte k_sig_bKGD[4] = { 0x62, 0x4b, 0x47, 0x44 };
static const png_byte k_sig_hIST[4] = { 0x68, 0x49, 0x53, 0x54 };
static const png_byte k_sig_sBIT[4] = { 0x73, 0x42, 0x49, 0x54 };
static const png_byte k_sig_dSIG[4] = { 0x64, 0x53, 0x49, 0x47 };
static const png_byte k_sig_acTL[4] = { 0x61, 0x63, 0x54, 0x4c };
static const png_byte k_sig_fcTL[4] = { 0x66, 0x63, 0x54, 0x4c };
static const png_byte k_sig_fdAT[4] = { 0x66, 0x64, 0x41, 0x54 };

/*
 * The OptiPNG encoder limits (and limitations).
 */
static const opng_fsize_t k_idat_size_max = PNG_UINT_31_MAX;
static const char *k_idat_size_max_string = "2GB";

/*
 * Status flags.
 */
enum
{
    INPUT_IS_PNG_FILE           = 0x0001,
    INPUT_HAS_PNG_DATASTREAM    = 0x0002,
    INPUT_HAS_PNG_SIGNATURE     = 0x0004,
    INPUT_HAS_DIGITAL_SIGNATURE = 0x0008,
    INPUT_HAS_MULTIPLE_IMAGES   = 0x0010,
    INPUT_HAS_APNG              = 0x0020,
    INPUT_HAS_STRIPPED_DATA     = 0x0040,
    INPUT_HAS_JUNK              = 0x0080,
    INPUT_HAS_ERRORS            = 0x0100,
    OUTPUT_NEEDS_NEW_FILE       = 0x1000,
    OUTPUT_NEEDS_NEW_IDAT       = 0x2000,
    OUTPUT_HAS_ERRORS           = 0x4000
};

/*
 * The optimization engine.
 * (Since the engine is not thread-safe, there isn't much to put in here...)
 */
static struct opng_engine_struct
{
    int started;
} s_engine;

/*
 * The optimization process.
 */
static struct opng_process_struct
{
    unsigned int status;
    int num_iterations;
    opng_foffset_t in_datastream_offset;
    opng_fsize_t in_file_size, out_file_size;
    opng_fsize_t in_idat_size, out_idat_size;
    opng_fsize_t best_idat_size, max_idat_size;
    png_uint_32 in_plte_trns_size, out_plte_trns_size;
    png_uint_32 reductions;
    opng_bitset_t compr_level_set, mem_level_set, strategy_set, filter_set;
    int best_compr_level, best_mem_level, best_strategy, best_filter;
} s_process;

/*
 * The optimization process summary.
 */
static struct opng_summary_struct
{
    unsigned int file_count;
    unsigned int err_count;
    unsigned int fix_count;
    unsigned int snip_count;
} s_summary;

/*
 * The optimized image.
 */
static struct opng_image_struct
{
    png_uint_32 width;             /* IHDR */
    png_uint_32 height;
    int bit_depth;
    int color_type;
    int compression_type;
    int filter_type;
    int interlace_type;
    png_bytepp row_pointers;       /* IDAT */
    png_colorp palette;            /* PLTE */
    int num_palette;
    png_color_16p background_ptr;  /* bKGD */
    png_color_16 background;
    png_uint_16p hist;             /* hIST */
    png_color_8p sig_bit_ptr;      /* sBIT */
    png_color_8 sig_bit;
    png_bytep trans_alpha;         /* tRNS */
    int num_trans;
    png_color_16p trans_color_ptr;
    png_color_16 trans_color;
    png_unknown_chunkp unknowns;   /* everything else */
    int num_unknowns;
} s_image;

/*
 * The user options.
 */
static struct opng_options s_options;

/*
 * More global variables, for quick access and bonus style points.
 */
static png_structp s_read_ptr;
static png_infop s_read_info_ptr;
static png_structp s_write_ptr;
static png_infop s_write_info_ptr;


/*
 * The user interface callbacks.
 */
static void (*usr_printf)(const char *fmt, ...);
static void (*usr_print_cntrl)(int cntrl_code);
static void (*usr_progress)(unsigned long num, unsigned long denom);
static void (*usr_panic)(const char *msg);


/*
 * Internal debugging tool.
 */
#define OPNG_ENSURE(cond, msg) \
    { if (!(cond)) usr_panic(msg); }  /* strong check, no #ifdef's */


/*
 * Size ratio display.
 */
static void
opng_print_fsize_ratio(opng_fsize_t num, opng_fsize_t denom)
{
#if OPNG_FSIZE_MAX <= ULONG_MAX
#define RATIO_TYPE struct opng_ulratio
#define RATIO_CONV_FN opng_ulratio_to_factor_string
#else
#define RATIO_TYPE struct opng_ullratio
#define RATIO_CONV_FN opng_ullratio_to_factor_string
#endif

    char buffer[32];
    RATIO_TYPE ratio;
    int result;

    ratio.num = num;
    ratio.denom = denom;
    result = RATIO_CONV_FN(buffer, sizeof(buffer), &ratio);
    usr_printf("%s%s", buffer, (result > 0) ? "" : "...");

#undef RATIO_TYPE
#undef RATIO_CONV_FN
}

/*
 * Size change display.
 */
static void
opng_print_fsize_difference(opng_fsize_t init_size, opng_fsize_t final_size,
                            int show_ratio)
{
    opng_fsize_t difference;
    int sign;

    if (init_size <= final_size)
    {
        sign = 0;
        difference = final_size - init_size;
    }
    else
    {
        sign = 1;
        difference = init_size - final_size;
    }

    if (difference == 0)
    {
        usr_printf("no change");
        return;
    }
    if (difference == 1)
        usr_printf("1 byte");
    else
        usr_printf("%" OPNG_FSIZE_PRIu " bytes", difference);
    if (show_ratio && init_size > 0)
    {
        usr_printf(" = ");
        opng_print_fsize_ratio(difference, init_size);
    }
    usr_printf((sign == 0) ? " increase" : " decrease");
}

/*
 * Image info display.
 */
static void
opng_print_image_info(int show_dim, int show_depth, int show_type,
                      int show_interlaced)
{
    static const int type_channels[8] = {1, 0, 3, 1, 2, 0, 4, 0};
    int channels, printed;

    printed = 0;
    if (show_dim)
    {
        printed = 1;
        usr_printf("%lux%lu pixels",
                   (unsigned long)s_image.width,
                   (unsigned long)s_image.height);
    }
    if (show_depth)
    {
        if (printed)
            usr_printf(", ");
        printed = 1;
        channels = type_channels[s_image.color_type & 7];
        if (channels != 1)
            usr_printf("%dx%d bits/pixel", channels, s_image.bit_depth);
        else if (s_image.bit_depth != 1)
            usr_printf("%d bits/pixel", s_image.bit_depth);
        else
            usr_printf("1 bit/pixel");
    }
    if (show_type)
    {
        if (printed)
            usr_printf(", ");
        printed = 1;
        if (s_image.color_type & PNG_COLOR_MASK_PALETTE)
        {
            if (s_image.num_palette == 1)
                usr_printf("1 color");
            else
                usr_printf("%d colors", s_image.num_palette);
            if (s_image.num_trans > 0)
                usr_printf(" (%d transparent)", s_image.num_trans);
            usr_printf(" in palette");
        }
        else
        {
            usr_printf((s_image.color_type & PNG_COLOR_MASK_COLOR) ?
                       "RGB" : "grayscale");
            if (s_image.color_type & PNG_COLOR_MASK_ALPHA)
                usr_printf("+alpha");
            else if (s_image.trans_color_ptr != NULL)
                usr_printf("+transparency");
        }
    }
    if (show_interlaced)
    {
        if (s_image.interlace_type != PNG_INTERLACE_NONE)
        {
            if (printed)
                usr_printf(", ");
            usr_printf("interlaced");
        }
    }
}

/*
 * Warning display.
 */
static void
opng_print_warning(const char *msg)
{
    usr_print_cntrl('\v');  /* VT: new paragraph */
    usr_printf("Warning: %s\n", msg);
}

/*
 * Error display.
 */
static void
opng_print_error(const char *msg)
{
    usr_print_cntrl('\v');  /* VT: new paragraph */
    usr_printf("Error: %s\n", msg);
}

/*
 * Error thrower.
 */
static void
opng_throw_error(png_const_charp msg)
{
    opng_print_error(msg);
    Throw OPNG_STATUS_ERR_OPTIPNG;
}

/*
 * Warning handler for libpng.
 */
static void
opng_warning(png_structp png_ptr, png_const_charp msg)
{
    /* Error in input or output file; processing may continue. */
    /* Recovery requires (re)compression of IDAT. */
    if (png_ptr == s_read_ptr)
        s_process.status |= (INPUT_HAS_ERRORS | OUTPUT_NEEDS_NEW_IDAT);
    opng_print_warning(msg);
}

/*
 * Error handler for libpng.
 */
static void
opng_error(png_structp png_ptr, png_const_charp msg)
{
    /* Error in input or output file; processing must stop. */
    /* Recovery requires (re)compression of IDAT. */
    if (png_ptr == s_read_ptr)
    {
        s_process.status |= (INPUT_HAS_ERRORS | OUTPUT_NEEDS_NEW_IDAT);
        if (opng_validate_image(s_read_ptr, s_read_info_ptr))
        {
            /* The critical info has been loaded.
             * Treat this error as a warning, to allow data recovery.
             */
            opng_print_warning(msg);
            Throw OPNG_STATUS_OK;
        }
    }

    opng_print_error(msg);
    Throw OPNG_STATUS_ERR_LIBPNG;
}

/*
 * Memory deallocator.
 */
static void
opng_free(void *ptr)
{
    /* This deallocator must be compatible with libpng's memory allocation
     * routines, png_malloc() and png_free().
     * If those routines change, this one must be changed accordingly.
     */
    free(ptr);
}

/*
 * IDAT size checker.
 */
static void
opng_check_idat_size(opng_fsize_t size)
{
    if (size > k_idat_size_max)
        opng_throw_error("IDAT sizes larger than the maximum chunk size "
                         "are currently unsupported");
}

/*
 * Chunk handler.
 */
static void
opng_set_keep_unknown_chunk(png_structp png_ptr,
                            int keep, png_bytep chunk_type)
{
    png_byte chunk_name[5];

    /* Call png_set_keep_unknown_chunks() once per each chunk type only. */
    memcpy(chunk_name, chunk_type, 4);
    chunk_name[4] = 0;
    if (!png_handle_as_unknown(png_ptr, chunk_name))
        png_set_keep_unknown_chunks(png_ptr, keep, chunk_name, 1);
}

/*
 * Chunk categorization.
 */
static int
opng_is_image_chunk(png_bytep chunk_type)
{
    if ((chunk_type[0] & 0x20) == 0)
        return 1;
    /* Although tRNS is listed as ancillary in the PNG specification, it stores
     * alpha samples, which is critical information. For example, tRNS cannot
     * be generally ignored when rendering animations.
     * Operations claimed to be lossless must treat tRNS as a critical chunk.
     */
    if (memcmp(chunk_type, k_sig_tRNS, 4) == 0)
        return 1;
    return 0;
}

/*
 * Chunk categorization.
 */
static int
opng_is_apng_chunk(png_bytep chunk_type)
{
    if (memcmp(chunk_type, k_sig_acTL, 4) == 0 ||
        memcmp(chunk_type, k_sig_fcTL, 4) == 0 ||
        memcmp(chunk_type, k_sig_fdAT, 4) == 0)
        return 1;
    return 0;
}

/*
 * Chunk filter.
 */
static int
opng_allow_chunk(png_bytep chunk_type)
{
    /* Always allow critical chunks and tRNS. */
    if (opng_is_image_chunk(chunk_type))
        return 1;
    /* Block all the other chunks if requested. */
    if (s_options.strip_all)
        return 0;
    /* Always block the digital signature chunks. */
    if (memcmp(chunk_type, k_sig_dSIG, 4) == 0)
        return 0;
    /* Block the APNG chunks when snipping. */
    if (s_options.snip && opng_is_apng_chunk(chunk_type))
        return 0;
    /* Allow all the other chunks. */
    return 1;
}

/*
 * Chunk handler.
 */
static void
opng_handle_chunk(png_structp png_ptr, png_bytep chunk_type)
{
    int keep;

    if (opng_is_image_chunk(chunk_type))
        return;

    if (s_options.strip_all)
    {
        s_process.status |= INPUT_HAS_STRIPPED_DATA | INPUT_HAS_JUNK;
        opng_set_keep_unknown_chunk(png_ptr,
                                    PNG_HANDLE_CHUNK_NEVER, chunk_type);
        return;
    }

    /* Let libpng handle bKGD, hIST and sBIT. */
    if (memcmp(chunk_type, k_sig_bKGD, 4) == 0 ||
        memcmp(chunk_type, k_sig_hIST, 4) == 0 ||
        memcmp(chunk_type, k_sig_sBIT, 4) == 0)
        return;

    /* Everything else is handled as unknown by libpng. */
    keep = PNG_HANDLE_CHUNK_ALWAYS;
    if (memcmp(chunk_type, k_sig_dSIG, 4) == 0)
    {
        /* Recognize dSIG, but let libpng handle it as unknown. */
        s_process.status |= INPUT_HAS_DIGITAL_SIGNATURE;
    }
    else if (opng_is_apng_chunk(chunk_type))
    {
        /* Recognize APNG, but let libpng handle it as unknown. */
        s_process.status |= INPUT_HAS_APNG;
        if (memcmp(chunk_type, k_sig_fdAT, 4) == 0)
            s_process.status |= INPUT_HAS_MULTIPLE_IMAGES;
        if (s_options.snip)
        {
            s_process.status |= INPUT_HAS_JUNK;
            keep = PNG_HANDLE_CHUNK_NEVER;
        }
    }
    opng_set_keep_unknown_chunk(png_ptr, keep, chunk_type);
}

/*
 * Initialization for input handler.
 */
static void
opng_init_read_data(void)
{
    /* The relevant process data members are set to zero,
     * and nothing else needs to be done at this moment.
     */
}

/*
 * Initialization for output handler.
 */
static void
opng_init_write_data(void)
{
    s_process.out_file_size = 0;
    s_process.out_plte_trns_size = 0;
    s_process.out_idat_size = 0;
}

/*
 * Input handler.
 */
static void
opng_read_data(png_structp png_ptr, png_bytep data, size_t length)
{
    FILE *stream = (FILE *)png_get_io_ptr(png_ptr);
    int io_state = pngx_get_io_state(png_ptr);
    int io_state_loc = io_state & PNGX_IO_MASK_LOC;
    png_bytep chunk_sig;

    /* Read the data. */
    if (fread(data, 1, length, stream) != length)
        png_error(png_ptr,
                  "Can't read the input file or unexpected end of file");

    if (s_process.in_file_size == 0)
    {
        /* This is the first piece of PNG data. */
        OPNG_ENSURE(length == 8, "PNG I/O must start with the first 8 bytes");
        s_process.in_datastream_offset = opng_ftello(stream) - 8;
        s_process.status |= INPUT_HAS_PNG_DATASTREAM;
        if (io_state_loc == PNGX_IO_SIGNATURE)
            s_process.status |= INPUT_HAS_PNG_SIGNATURE;
        if (s_process.in_datastream_offset == 0)
            s_process.status |= INPUT_IS_PNG_FILE;
        else if (s_process.in_datastream_offset < 0)
            png_error(png_ptr,
                      "Can't get the file-position indicator in input file");
        s_process.in_file_size = (opng_fsize_t)s_process.in_datastream_offset;
    }
    s_process.in_file_size += length;

    /* Handle the OptiPNG-specific events. */
    OPNG_ENSURE((io_state & PNGX_IO_READING) && (io_state_loc != 0),
                "Incorrect info in png_ptr->io_state");
    if (io_state_loc == PNGX_IO_CHUNK_HDR)
    {
        /* In libpng 1.4.x and later, the chunk length and the chunk name
         * are serialized in a single operation. This is also ensured by
         * the opngio add-on for libpng 1.2.x and earlier.
         */
        OPNG_ENSURE(length == 8, "Reading chunk header, expecting 8 bytes");
        chunk_sig = data + 4;

        if (memcmp(chunk_sig, k_sig_IDAT, 4) == 0)
        {
            OPNG_ENSURE(png_ptr == s_read_ptr, "Incorrect I/O handler setup");
            if (png_get_rows(s_read_ptr, s_read_info_ptr) == NULL)
            {
                /* This is the first IDAT. */
                OPNG_ENSURE(s_process.in_idat_size == 0,
                            "Found IDAT with no rows");
                /* Allocate the rows here, bypassing libpng, and initialize
                 * their content. This allows recovery in case of subsequent
                 * errors.
                 */
                if (png_get_image_height(s_read_ptr, s_read_info_ptr) == 0)
                {
                    /* IDAT came before IHDR. An error will occur later. */
                    return;
                }
                OPNG_ENSURE(pngx_malloc_rows(s_read_ptr, s_read_info_ptr,
                                             0) != NULL,
                            "Failed allocation of image rows; "
                            "unsafe libpng allocator");
                png_data_freer(s_read_ptr, s_read_info_ptr,
                               PNG_USER_WILL_FREE_DATA, PNG_FREE_ROWS);
            }
            else
            {
                /* There is split IDAT overhead. Join IDATs. */
                s_process.status |= INPUT_HAS_JUNK;
            }
            s_process.in_idat_size += png_get_uint_32(data);
        }
        else if (memcmp(chunk_sig, k_sig_PLTE, 4) == 0 ||
                 memcmp(chunk_sig, k_sig_tRNS, 4) == 0)
        {
            /* Add the chunk overhead (header + CRC) to the data size. */
            s_process.in_plte_trns_size += png_get_uint_32(data) + 12;
        }
        else
            opng_handle_chunk(png_ptr, chunk_sig);
    }
    else if (io_state_loc == PNGX_IO_CHUNK_CRC)
    {
        OPNG_ENSURE(length == 4, "Reading chunk CRC, expecting 4 bytes");
    }
}

/*
 * Output handler.
 */
static void
opng_write_data(png_structp png_ptr, png_bytep data, size_t length)
{
    static int allow_crt_chunk;
    static int crt_chunk_is_idat;
    static opng_foffset_t crt_idat_offset;
    static opng_fsize_t crt_idat_size;
    static png_uint_32 crt_idat_crc;
    FILE *stream = (FILE *)png_get_io_ptr(png_ptr);
    int io_state = pngx_get_io_state(png_ptr);
    int io_state_loc = io_state & PNGX_IO_MASK_LOC;
    png_bytep chunk_sig;
    png_byte buf[4];

    OPNG_ENSURE((io_state & PNGX_IO_WRITING) && (io_state_loc != 0),
                "Incorrect info in png_ptr->io_state");

    /* Handle the OptiPNG-specific events. */
    if (io_state_loc == PNGX_IO_CHUNK_HDR)
    {
        OPNG_ENSURE(length == 8, "Writing chunk header, expecting 8 bytes");
        chunk_sig = data + 4;
        allow_crt_chunk = opng_allow_chunk(chunk_sig);
        if (memcmp(chunk_sig, k_sig_IDAT, 4) == 0)
        {
            crt_chunk_is_idat = 1;
            s_process.out_idat_size += png_get_uint_32(data);
            /* Abandon the trial if IDAT is bigger than the maximum allowed. */
            if (stream == NULL)
            {
                if (s_process.out_idat_size > s_process.max_idat_size)
                {
                    /* This is an early interruption, not an error. */
                    Throw OPNG_STATUS_OK;
                }
            }
        }
        else  /* not IDAT */
        {
            crt_chunk_is_idat = 0;
            if (memcmp(chunk_sig, k_sig_PLTE, 4) == 0 ||
                memcmp(chunk_sig, k_sig_tRNS, 4) == 0)
            {
                /* Add the chunk overhead (header + CRC) to the data size. */
                s_process.out_plte_trns_size += png_get_uint_32(data) + 12;
            }
        }
    }
    else if (io_state_loc == PNGX_IO_CHUNK_CRC)
    {
        OPNG_ENSURE(length == 4, "Writing chunk CRC, expecting 4 bytes");
    }

    /* Exit early if this is only a trial. */
    if (stream == NULL)
        return;

    /* Continue only if the current chunk type is allowed. */
    if (io_state_loc != PNGX_IO_SIGNATURE && !allow_crt_chunk)
        return;

    /* Here comes an elaborate way of writing the data, in which all IDATs
     * are joined into a single chunk.
     * Normally, the user-supplied I/O routines are not so complicated.
     */
    switch (io_state_loc)
    {
    case PNGX_IO_CHUNK_HDR:
        if (crt_chunk_is_idat)
        {
            if (crt_idat_offset == 0)
            {
                /* This is the header of the first IDAT. */
                crt_idat_offset = opng_ftello(stream);
                /* Try guessing the size of the final (joined) IDAT. */
                if (s_process.best_idat_size > 0)
                {
                    /* The guess is expected to be right. */
                    crt_idat_size = s_process.best_idat_size;
                }
                else
                {
                    /* The guess could be wrong.
                     * The size of the final IDAT will be revised.
                     */
                    crt_idat_size = length;
                }
                png_save_uint_32(data, (png_uint_32)crt_idat_size);
                /* Start computing the CRC of the final IDAT. */
                crt_idat_crc = crc32(0, k_sig_IDAT, 4);
            }
            else
            {
                /* This is not the first IDAT. Do not write its header. */
                return;
            }
        }
        else
        {
            if (crt_idat_offset != 0)
            {
                /* This is the header of the first chunk after IDAT.
                 * Finalize IDAT before resuming the normal operation.
                 */
                png_save_uint_32(buf, crt_idat_crc);
                if (fwrite(buf, 1, 4, stream) != 4)
                    io_state = 0;  /* error */
                s_process.out_file_size += 4;
                if (s_process.out_idat_size != crt_idat_size)
                {
                    /* The IDAT size has not been guessed correctly.
                     * It must be updated in a non-streamable way.
                     */
                    OPNG_ENSURE(s_process.best_idat_size == 0,
                                "Wrong guess of the output IDAT size");
                    opng_check_idat_size(s_process.out_idat_size);
                    png_save_uint_32(buf,
                                     (png_uint_32)s_process.out_idat_size);
                    if (opng_fwriteo(stream, crt_idat_offset, SEEK_SET,
                                     buf, 4) != 4)
                        io_state = 0;  /* error */
                }
                if (io_state == 0)
                    png_error(png_ptr, "Can't finalize IDAT");
                crt_idat_offset = 0;
            }
        }
        break;
    case PNGX_IO_CHUNK_DATA:
        if (crt_chunk_is_idat)
            crt_idat_crc = crc32(crt_idat_crc, data, length);
        break;
    case PNGX_IO_CHUNK_CRC:
        if (crt_chunk_is_idat)
        {
            /* Defer writing until the first non-IDAT occurs. */
            return;
        }
        break;
    }

    /* Write the data. */
    if (fwrite(data, 1, length, stream) != length)
        png_error(png_ptr, "Can't write the output file");
    s_process.out_file_size += length;
}

/*
 * Image info initialization.
 */
static void
opng_clear_image_info(void)
{
    memset(&s_image, 0, sizeof(s_image));
}

/*
 * Image info transfer.
 */
static void
opng_load_image_info(png_structp png_ptr, png_infop info_ptr, int load_meta)
{
    memset(&s_image, 0, sizeof(s_image));

    png_get_IHDR(png_ptr, info_ptr,
                 &s_image.width, &s_image.height, &s_image.bit_depth,
                 &s_image.color_type, &s_image.interlace_type,
                 &s_image.compression_type, &s_image.filter_type);
    s_image.row_pointers = png_get_rows(png_ptr, info_ptr);
    png_get_PLTE(png_ptr, info_ptr, &s_image.palette, &s_image.num_palette);
    /* Transparency is not considered metadata, although tRNS is ancillary.
     * See the comment in opng_is_image_chunk() above.
     */
    if (png_get_tRNS(png_ptr, info_ptr,
                     &s_image.trans_alpha,
                     &s_image.num_trans, &s_image.trans_color_ptr))
    {
        /* Double copying (pointer + value) is necessary here
         * due to an inconsistency in the libpng design.
         */
        if (s_image.trans_color_ptr != NULL)
        {
            s_image.trans_color = *s_image.trans_color_ptr;
            s_image.trans_color_ptr = &s_image.trans_color;
        }
    }

    if (!load_meta)
        return;

    if (png_get_bKGD(png_ptr, info_ptr, &s_image.background_ptr))
    {
        /* Same problem as in tRNS. */
        s_image.background = *s_image.background_ptr;
        s_image.background_ptr = &s_image.background;
    }
    png_get_hIST(png_ptr, info_ptr, &s_image.hist);
    if (png_get_sBIT(png_ptr, info_ptr, &s_image.sig_bit_ptr))
    {
        /* Same problem as in tRNS. */
        s_image.sig_bit = *s_image.sig_bit_ptr;
        s_image.sig_bit_ptr = &s_image.sig_bit;
    }
    s_image.num_unknowns =
        png_get_unknown_chunks(png_ptr, info_ptr, &s_image.unknowns);
}

/*
 * Image info transfer.
 */
static void
opng_store_image_info(png_structp png_ptr, png_infop info_ptr, int store_meta)
{
    int i;

    OPNG_ENSURE(s_image.row_pointers != NULL, "No info in image");

    png_set_IHDR(png_ptr, info_ptr,
                 s_image.width, s_image.height, s_image.bit_depth,
                 s_image.color_type, s_image.interlace_type,
                 s_image.compression_type, s_image.filter_type);
    png_set_rows(s_write_ptr, s_write_info_ptr, s_image.row_pointers);
    if (s_image.palette != NULL)
        png_set_PLTE(png_ptr, info_ptr, s_image.palette, s_image.num_palette);
    /* Transparency is not considered metadata, although tRNS is ancillary.
     * See the comment in opng_is_image_chunk() above.
     */
    if (s_image.trans_alpha != NULL || s_image.trans_color_ptr != NULL)
        png_set_tRNS(png_ptr, info_ptr,
                     s_image.trans_alpha,
                     s_image.num_trans, s_image.trans_color_ptr);

    if (!store_meta)
        return;

    if (s_image.background_ptr != NULL)
        png_set_bKGD(png_ptr, info_ptr, s_image.background_ptr);
    if (s_image.hist != NULL)
        png_set_hIST(png_ptr, info_ptr, s_image.hist);
    if (s_image.sig_bit_ptr != NULL)
        png_set_sBIT(png_ptr, info_ptr, s_image.sig_bit_ptr);
    if (s_image.num_unknowns != 0)
    {
        png_set_unknown_chunks(png_ptr, info_ptr,
                               s_image.unknowns, s_image.num_unknowns);
        /* This should be handled by libpng. */
        for (i = 0; i < s_image.num_unknowns; ++i)
            png_set_unknown_chunk_location(png_ptr, info_ptr,
                                           i, s_image.unknowns[i].location);
    }
}

/*
 * Image info destruction.
 */
static void
opng_destroy_image_info(void)
{
    png_uint_32 i;
    int j;

    if (s_image.row_pointers == NULL)
        return;  /* nothing to clean up */

    for (i = 0; i < s_image.height; ++i)
        opng_free(s_image.row_pointers[i]);
    opng_free(s_image.row_pointers);
    opng_free(s_image.palette);
    opng_free(s_image.trans_alpha);
    opng_free(s_image.hist);
    for (j = 0; j < s_image.num_unknowns; ++j)
        opng_free(s_image.unknowns[j].data);
    opng_free(s_image.unknowns);
    /* DO NOT deallocate background_ptr, sig_bit_ptr, trans_color_ptr.
     * See the comments regarding double copying inside opng_load_image_info().
     */

    /* Clear the space here and do not worry about double-deallocation issues
     * that might arise later on.
     */
    memset(&s_image, 0, sizeof(s_image));
}

/*
 * Image file reading.
 */
static void
opng_read_file(FILE *infile)
{
    const char *fmt_name;
    int num_img;
    png_uint_32 reductions;
    volatile opng_status_t status;  /* volatile is required by cexcept */

    status = OPNG_STATUS_OK;
    Try
    {
        s_read_ptr = png_create_read_struct(PNG_LIBPNG_VER_STRING,
                                            NULL, opng_error, opng_warning);
        s_read_info_ptr = png_create_info_struct(s_read_ptr);
        if (s_read_info_ptr == NULL)
            opng_throw_error("Can't create image decoder");

        /* Override the default libpng settings. */
        png_set_keep_unknown_chunks(s_read_ptr,
                                    PNG_HANDLE_CHUNK_ALWAYS, NULL, 0);
        png_set_user_limits(s_read_ptr, PNG_UINT_31_MAX, PNG_UINT_31_MAX);

        /* Read the input image file. */
        opng_init_read_data();
        pngx_set_read_fn(s_read_ptr, infile, opng_read_data);
        fmt_name = NULL;
        num_img = pngx_read_image(s_read_ptr, s_read_info_ptr,
                                  &fmt_name, NULL);
        if (num_img <= 0)
            opng_throw_error("Unrecognized image file format");
        if (num_img > 1)
            s_process.status |= INPUT_HAS_MULTIPLE_IMAGES;
        if ((s_process.status & INPUT_IS_PNG_FILE) &&
            (s_process.status & INPUT_HAS_MULTIPLE_IMAGES))
        {
            /* pngxtern can't distinguish between APNG and proper PNG. */
            fmt_name = (s_process.status & INPUT_HAS_PNG_SIGNATURE) ?
                       "APNG" : "APNG datastream";
        }
        OPNG_ENSURE(fmt_name != NULL, "No format name from pngxtern");

        if (s_process.in_file_size == 0)
        {
            if (opng_fgetsize(infile, &s_process.in_file_size) < 0)
            {
                opng_print_warning("Can't get the correct file size");
                s_process.in_file_size = 0;
            }
        }
    }
    Catch (status)
    {
        if (opng_validate_image(s_read_ptr, s_read_info_ptr))
            OPNG_ENSURE(status == OPNG_STATUS_OK,
                        "Mysterious error in validated image file");
    }

    Try
    {
        if (status != OPNG_STATUS_OK)
            Throw status;

        /* Display format and image information. */
        if (strcmp(fmt_name, "PNG") != 0)
        {
            usr_printf("Importing %s", fmt_name);
            if (s_process.status & INPUT_HAS_MULTIPLE_IMAGES)
            {
                if (!(s_process.status & INPUT_IS_PNG_FILE))
                    usr_printf(" (multi-image or animation)");
                if (s_options.snip)
                    usr_printf("; snipping...");
            }
            usr_printf("\n");
        }
        opng_load_image_info(s_read_ptr, s_read_info_ptr, 1);
        opng_print_image_info(1, 1, 1, 1);
        usr_printf("\n");

        /* Choose the applicable image reductions. */
        reductions = OPNG_REDUCE_ALL & ~OPNG_REDUCE_METADATA;
        if (s_options.nb)
            reductions &= ~OPNG_REDUCE_BIT_DEPTH;
        if (s_options.nc)
            reductions &= ~OPNG_REDUCE_COLOR_TYPE;
        if (s_options.np)
            reductions &= ~OPNG_REDUCE_PALETTE;
        if (s_options.nz && (s_process.status & INPUT_HAS_PNG_DATASTREAM))
        {
            /* Do not reduce files with PNG datastreams under -nz. */
            reductions = OPNG_REDUCE_NONE;
        }
        if (s_process.status & INPUT_HAS_DIGITAL_SIGNATURE)
        {
            /* Do not reduce signed files. */
            reductions = OPNG_REDUCE_NONE;
        }
        if ((s_process.status & INPUT_IS_PNG_FILE) &&
            (s_process.status & INPUT_HAS_MULTIPLE_IMAGES) &&
            (reductions != OPNG_REDUCE_NONE) &&
            !s_options.snip)
        {
            usr_printf(
                "Can't reliably reduce APNG file; disabling reductions.\n"
                "(Did you want to -snip and optimize the first frame?)\n");
            reductions = OPNG_REDUCE_NONE;
        }

        /* Try to reduce the image. */
        s_process.reductions =
            opng_reduce_image(s_read_ptr, s_read_info_ptr, reductions);

        /* If the image is reduced, enforce full compression. */
        if (s_process.reductions != OPNG_REDUCE_NONE)
        {
            opng_load_image_info(s_read_ptr, s_read_info_ptr, 1);
            usr_printf("Reducing image to ");
            opng_print_image_info(0, 1, 1, 0);
            usr_printf("\n");
        }

        /* Change the interlace type if required. */
        if (s_options.interlace >= 0 &&
            s_image.interlace_type != s_options.interlace)
        {
            s_image.interlace_type = s_options.interlace;
            /* A change in interlacing requires IDAT recoding. */
            s_process.status |= OUTPUT_NEEDS_NEW_IDAT;
        }
    }
    Catch (status)
    {
        /* Do the cleanup, then rethrow the exception. */
        png_data_freer(s_read_ptr, s_read_info_ptr,
                       PNG_DESTROY_WILL_FREE_DATA, PNG_FREE_ALL);
        png_destroy_read_struct(&s_read_ptr, &s_read_info_ptr, NULL);
        Throw status;
    }

    /* Destroy the libpng structures, but leave the enclosed data intact
     * to allow further processing.
     */
    png_data_freer(s_read_ptr, s_read_info_ptr,
                   PNG_USER_WILL_FREE_DATA, PNG_FREE_ALL);
    png_destroy_read_struct(&s_read_ptr, &s_read_info_ptr, NULL);
}

/*
 * PNG file writing.
 *
 * If the output file is NULL, PNG encoding is still done,
 * but no file is written.
 */
static void
opng_write_file(FILE *outfile,
                int compression_level, int memory_level,
                int compression_strategy, int filter)
{
    volatile opng_status_t status;  /* volatile is required by cexcept */

    OPNG_ENSURE(compression_level >= OPNG_COMPR_LEVEL_MIN &&
                compression_level <= OPNG_COMPR_LEVEL_MAX &&
                memory_level >= OPNG_MEM_LEVEL_MIN &&
                memory_level <= OPNG_MEM_LEVEL_MAX &&
                compression_strategy >= OPNG_STRATEGY_MIN &&
                compression_strategy <= OPNG_STRATEGY_MAX &&
                filter >= OPNG_FILTER_MIN &&
                filter <= OPNG_FILTER_MAX,
                "Invalid encoding parameters");

    status = OPNG_STATUS_OK;
    Try
    {
        s_write_ptr = png_create_write_struct(PNG_LIBPNG_VER_STRING,
                                              NULL, opng_error, opng_warning);
        s_write_info_ptr = png_create_info_struct(s_write_ptr);
        if (s_write_info_ptr == NULL)
            opng_throw_error("Can't create image encoder");

        png_set_compression_level(s_write_ptr, compression_level);
        png_set_compression_mem_level(s_write_ptr, memory_level);
        png_set_compression_strategy(s_write_ptr, compression_strategy);
        png_set_filter(s_write_ptr, PNG_FILTER_TYPE_BASE,
                       k_filter_table[filter]);
        if (compression_strategy != Z_HUFFMAN_ONLY &&
            compression_strategy != Z_RLE)
        {
            if (s_options.window_bits > 0)
                png_set_compression_window_bits(s_write_ptr,
                                                s_options.window_bits);
        }
        else
        {
#ifdef WBITS_8_OK
            png_set_compression_window_bits(s_write_ptr, 8);
#else
            png_set_compression_window_bits(s_write_ptr, 9);
#endif
        }

        /* Override the default libpng settings. */
        png_set_keep_unknown_chunks(s_write_ptr,
                                    PNG_HANDLE_CHUNK_ALWAYS, NULL, 0);
        png_set_user_limits(s_write_ptr, PNG_UINT_31_MAX, PNG_UINT_31_MAX);

        /* Write the PNG stream. */
        opng_store_image_info(s_write_ptr, s_write_info_ptr, outfile != NULL);
        opng_init_write_data();
        pngx_set_write_fn(s_write_ptr, outfile, opng_write_data, NULL);
        png_write_png(s_write_ptr, s_write_info_ptr, 0, NULL);
    }
    Catch (status)
    {
        /* Set IDAT size to invalid. */
        s_process.out_idat_size = k_idat_size_max + 1;
    }

    /* Destroy the libpng structures. */
    png_destroy_write_struct(&s_write_ptr, &s_write_info_ptr);

    if (status != OPNG_STATUS_OK)
        Throw status;
}

/*
 * PNG file copying.
 */
static void
opng_copy_file(FILE *infile, FILE *outfile)
{
    volatile png_bytep buf;  /* volatile is required by cexcept */
    const png_uint_32 buf_size_incr = 0x1000;
    png_uint_32 buf_size, length;
    png_byte chunk_hdr[8];
    volatile opng_status_t status;  /* volatile is required by cexcept */

    s_write_ptr = png_create_write_struct(PNG_LIBPNG_VER_STRING,
                                          NULL, opng_error, opng_warning);
    if (s_write_ptr == NULL)
        opng_throw_error("Can't create image encoder");
    opng_init_write_data();
    pngx_set_write_fn(s_write_ptr, outfile, opng_write_data, NULL);

    status = OPNG_STATUS_OK;
    Try
    {
        buf = NULL;
        buf_size = 0;

        /* Write the signature in the output file. */
        pngx_write_sig(s_write_ptr);

        /* Copy all chunks until IEND. */
        /* Error checking is done only at a very basic level. */
        do
        {
            if (fread(chunk_hdr, 8, 1, infile) != 1)  /* length + name */
                opng_throw_error("Read error");
            length = png_get_uint_32(chunk_hdr);
            if (length > PNG_UINT_31_MAX)
            {
                if (buf == NULL && length == 0x89504e47UL)  /* "\x89PNG" */
                {
                    /* Skip the signature. */
                    continue;
                }
                opng_throw_error("Data error");
            }
            if (length + 4 > buf_size)
            {
                png_free(s_write_ptr, buf);
                buf_size =
                    (((length + 4) + (buf_size_incr - 1)) / buf_size_incr) *
                    buf_size_incr;
                buf = (png_bytep)png_malloc(s_write_ptr, buf_size);
                /* Do not use realloc() here, it's slower. */
            }
            if (fread(buf, length + 4, 1, infile) != 1)  /* data + crc */
                opng_throw_error("Read error");
            png_write_chunk(s_write_ptr, chunk_hdr + 4, buf, length);
        } while (memcmp(chunk_hdr + 4, k_sig_IEND, 4) != 0);
    }
    Catch (status)
    {
    }

    png_free(s_write_ptr, buf);
    png_destroy_write_struct(&s_write_ptr, NULL);

    if (status != OPNG_STATUS_OK)
        Throw status;
}

/*
 * Iteration initialization.
 */
static void
opng_init_iteration(opng_bitset_t cmdline_set, opng_bitset_t mask_set,
                    const char *preset, opng_bitset_t *output_set)
{
    opng_bitset_t preset_set;
    int check;

    *output_set = cmdline_set & mask_set;
    if (*output_set == 0 && cmdline_set != 0)
        opng_throw_error("Iteration parameter(s) out of range");
    if (s_options.optim_level >= 0 || *output_set == 0)
    {
        check =
            opng_strparse_rangeset_to_bitset(&preset_set, preset, mask_set);
        OPNG_ENSURE(check == 0, "[internal] Invalid preset");
        *output_set |= preset_set & mask_set;
    }
}

/*
 * Iteration initialization.
 */
static void
opng_init_iterations(void)
{
    opng_bitset_t compr_level_set, mem_level_set, strategy_set, filter_set;
    opng_bitset_t strategy_singles_set;
    int preset_index;
    int t1, t2;

    /* Set the IDAT size limit. The trials that pass this limit will be
     * abandoned, as there will be no need to wait until their completion.
     * This limit may further decrease as iterations go on.
     */
    if (s_options.full || (s_process.status & OUTPUT_NEEDS_NEW_IDAT))
        s_process.max_idat_size = k_idat_size_max;
    else
    {
        OPNG_ENSURE(s_process.in_idat_size > 0, "No IDAT in input");
        /* Add the input PLTE and tRNS sizes to the initial max IDAT size,
         * to account for the changes that may occur during reduction.
         * This incurs a negligible overhead on processing only: the final
         * IDAT size will not be affected, because a precise check will be
         * performed at the end, inside opng_finish_iterations().
         */
        s_process.max_idat_size =
            s_process.in_idat_size + s_process.in_plte_trns_size;
    }

    /* Get preset_index from s_options.optim_level, but leave the latter
     * intact, because the effect of "optipng -o2 -z... -f..." is slightly
     * different from the effect of "optipng -z... -f..." (without "-o").
     */
    preset_index = s_options.optim_level;
    if (preset_index < 0)
        preset_index = OPNG_OPTIM_LEVEL_DEFAULT;
    else if (preset_index > OPNG_OPTIM_LEVEL_MAX)
        preset_index = OPNG_OPTIM_LEVEL_MAX;

    /* Initialize the iteration sets.
     * Combine the user-defined values with the optimization presets.
     */
    opng_init_iteration(s_options.compr_level_set, OPNG_COMPR_LEVEL_SET_MASK,
                        k_presets[preset_index].compr_level, &compr_level_set);
    opng_init_iteration(s_options.mem_level_set, OPNG_MEM_LEVEL_SET_MASK,
                        k_presets[preset_index].mem_level, &mem_level_set);
    opng_init_iteration(s_options.strategy_set, OPNG_STRATEGY_SET_MASK,
                        k_presets[preset_index].strategy, &strategy_set);
    opng_init_iteration(s_options.filter_set, OPNG_FILTER_SET_MASK,
                        k_presets[preset_index].filter, &filter_set);

    /* Replace the empty sets with the libpng's "best guess" heuristics. */
    if (compr_level_set == 0)
        opng_bitset_set(&compr_level_set, Z_BEST_COMPRESSION);  /* -zc9 */
    if (mem_level_set == 0)
        opng_bitset_set(&mem_level_set, 8);
    if (s_image.bit_depth < 8 || s_image.palette != NULL)
    {
        if (strategy_set == 0)
            opng_bitset_set(&strategy_set, Z_DEFAULT_STRATEGY);  /* -zs0 */
        if (filter_set == 0)
            opng_bitset_set(&filter_set, 0);  /* -f0 */
    }
    else
    {
        if (strategy_set == 0)
            opng_bitset_set(&strategy_set, Z_FILTERED);  /* -zs1 */
        if (filter_set == 0)
            opng_bitset_set(&filter_set, 5);  /* -f0 */
    }

    /* Store the results into process. */
    s_process.compr_level_set = compr_level_set;
    s_process.mem_level_set = mem_level_set;
    s_process.strategy_set = strategy_set;
    s_process.filter_set = filter_set;
    strategy_singles_set = (1 << Z_HUFFMAN_ONLY) | (1 << Z_RLE);
    t1 = opng_bitset_count(compr_level_set) *
         opng_bitset_count(strategy_set & ~strategy_singles_set);
    t2 = opng_bitset_count(strategy_set & strategy_singles_set);
    s_process.num_iterations = (t1 + t2) *
                               opng_bitset_count(mem_level_set) *
                               opng_bitset_count(filter_set);
    OPNG_ENSURE(s_process.num_iterations > 0, "Invalid iteration parameters");
}

/*
 * Iteration.
 */
static void
opng_iterate(void)
{
    opng_bitset_t compr_level_set, mem_level_set, strategy_set, filter_set;
    int compr_level, mem_level, strategy, filter;
    int counter;
    int line_reused;

    OPNG_ENSURE(s_process.num_iterations > 0, "Iterations not initialized");

    compr_level_set = s_process.compr_level_set;
    mem_level_set = s_process.mem_level_set;
    strategy_set = s_process.strategy_set;
    filter_set = s_process.filter_set;

    if ((s_process.num_iterations == 1) &&
        (s_process.status & OUTPUT_NEEDS_NEW_IDAT))
    {
        /* There is only one combination. Select it and return. */
        s_process.best_idat_size = 0;  /* unknown */
        s_process.best_compr_level = opng_bitset_find_first(compr_level_set);
        s_process.best_mem_level = opng_bitset_find_first(mem_level_set);
        s_process.best_strategy = opng_bitset_find_first(strategy_set);
        s_process.best_filter = opng_bitset_find_first(filter_set);
        return;
    }

    /* Prepare for the big iteration. */
    s_process.best_idat_size = k_idat_size_max + 1;
    s_process.best_compr_level = -1;
    s_process.best_mem_level = -1;
    s_process.best_strategy = -1;
    s_process.best_filter = -1;

    /* Iterate through the "hyper-rectangle" (zc, zm, zs, f). */
    usr_printf("\nTrying:\n");
    line_reused = 0;
    counter = 0;
    for (filter = OPNG_FILTER_MIN;
         filter <= OPNG_FILTER_MAX;
         ++filter)
    {
        if (!opng_bitset_test(filter_set, filter))
            continue;
        for (strategy = OPNG_STRATEGY_MIN;
             strategy <= OPNG_STRATEGY_MAX;
             ++strategy)
        {
            if (!opng_bitset_test(strategy_set, strategy))
                continue;
            if (strategy == Z_HUFFMAN_ONLY)
            {
                /* Under Z_HUFFMAN_ONLY, all compression levels
                 * (deflate_fast and deflate_slow combined)
                 * produce the same output. Pick level 1.
                 */
                compr_level_set = 0;
                opng_bitset_set(&compr_level_set, 1);
            }
            else if (strategy == Z_RLE)
            {
                /* Under Z_RLE, all deflate_fast compression levels produce
                 * the same output. Ditto about the deflate_slow levels.
                 * Pick level 9, in preference for deflate_slow.
                 */
                compr_level_set = 0;
                opng_bitset_set(&compr_level_set, 9);
            }
            else
            {
                /* Restore compr_level_set. */
                compr_level_set = s_process.compr_level_set;
            }
            for (compr_level = OPNG_COMPR_LEVEL_MAX;
                 compr_level >= OPNG_COMPR_LEVEL_MIN;
                 --compr_level)
            {
                if (!opng_bitset_test(compr_level_set, compr_level))
                    continue;
                for (mem_level = OPNG_MEM_LEVEL_MAX;
                     mem_level >= OPNG_MEM_LEVEL_MIN;
                     --mem_level)
                {
                    if (!opng_bitset_test(mem_level_set, mem_level))
                        continue;
                    usr_printf("  zc = %d  zm = %d  zs = %d  f = %d",
                               compr_level, mem_level, strategy, filter);
                    usr_progress(counter, s_process.num_iterations);
                    ++counter;
                    opng_write_file(NULL,
                                    compr_level, mem_level, strategy, filter);
                    if (s_process.out_idat_size > k_idat_size_max)
                    {
                        if (s_options.verbose)
                        {
                            usr_printf("\t\tIDAT too big\n");
                            line_reused = 0;
                        }
                        else
                        {
                            usr_print_cntrl('\r');  /* CR: reset line */
                            line_reused = 1;
                        }
                        continue;
                    }
                    usr_printf("\t\tIDAT size = %" OPNG_FSIZE_PRIu "\n",
                               s_process.out_idat_size);
                    line_reused = 0;
                    if (s_process.best_idat_size < s_process.out_idat_size)
                    {
                        /* The current best size is smaller than the last size.
                         * Discard the last iteration.
                         */
                        continue;
                    }
                    if (s_process.best_idat_size == s_process.out_idat_size &&
                        (s_process.best_strategy == Z_HUFFMAN_ONLY ||
                         s_process.best_strategy == Z_RLE))
                    {
                        /* The current best size is equal to the last size;
                         * the current best strategy is already the fastest.
                         * Discard the last iteration.
                         */
                        continue;
                    }
                    s_process.best_compr_level = compr_level;
                    s_process.best_mem_level = mem_level;
                    s_process.best_strategy = strategy;
                    s_process.best_filter = filter;
                    s_process.best_idat_size = s_process.out_idat_size;
                    if (!s_options.full)
                        s_process.max_idat_size = s_process.out_idat_size;
                }
            }
        }
    }
    if (line_reused)
        usr_print_cntrl(-31);  /* minus N: erase N chars from start of line */

    OPNG_ENSURE(counter == s_process.num_iterations,
                "Inconsistent iteration counter");
    usr_progress(counter, s_process.num_iterations);
}

/*
 * Iteration finalization.
 */
static void
opng_finish_iterations(void)
{
    if (s_process.best_idat_size + s_process.out_plte_trns_size <
        s_process.in_idat_size + s_process.in_plte_trns_size)
        s_process.status |= OUTPUT_NEEDS_NEW_IDAT;
    if (s_process.status & OUTPUT_NEEDS_NEW_IDAT)
    {
        if (s_process.best_idat_size <= k_idat_size_max)
        {
            usr_printf("\nSelecting parameters:\n");
            usr_printf("  zc = %d  zm = %d  zs = %d  f = %d",
                       s_process.best_compr_level,
                       s_process.best_mem_level,
                       s_process.best_strategy,
                       s_process.best_filter);
            if (s_process.best_idat_size > 0)
            {
                /* At least one trial has been run. */
                usr_printf("\t\tIDAT size = %" OPNG_FSIZE_PRIu,
                           s_process.best_idat_size);
            }
            usr_printf("\n");
        }
        else
        {
            /* The compressed image data is larger than the maximum allowed. */
            usr_printf("  zc = *  zm = *  zs = *  f = *\t\tIDAT size > %s\n",
                       k_idat_size_max_string);
        }
    }
}

/*
 * Image file optimization.
 */
static void
opng_optimize_impl(const char *infile_name)
{
    static FILE *infile, *outfile;         /* static or volatile is required */
    static const char *infile_name_local;                      /* by cexcept */
    static const char *outfile_name, *bakfile_name;
    static int new_outfile, has_backup;
    char name_buf[FILENAME_MAX], tmp_buf[FILENAME_MAX];
    volatile opng_status_t status;  /* volatile is required by cexcept */

    memset(&s_process, 0, sizeof(s_process));
    if (s_options.force)
        s_process.status |= OUTPUT_NEEDS_NEW_IDAT;

    infile_name_local = infile_name;
    if ((infile = fopen(infile_name_local, "rb")) == NULL)
        opng_throw_error("Can't open the input file");

    status = OPNG_STATUS_OK;
    Try
    {
        opng_read_file(infile);
    }
    Catch (status)
    {
        OPNG_ENSURE(status != OPNG_STATUS_OK,
                    "opng_read_file should throw errors only");
    }
    fclose(infile);  /* finally */
    if (status != OPNG_STATUS_OK)
        Throw status;  /* rethrow */

    /* Check the error flag. This must be the first check. */
    if (s_process.status & INPUT_HAS_ERRORS)
    {
        usr_printf("Recoverable errors found in input.");
        if (s_options.fix)
        {
            usr_printf(" Fixing...\n");
            s_process.status |= OUTPUT_NEEDS_NEW_FILE;
        }
        else
        {
            usr_printf(" Rerun " PROGRAM_NAME " with -fix enabled.\n");
            opng_throw_error("Previous error(s) not fixed");
        }
    }

    /* Check the junk flag. */
    if (s_process.status & INPUT_HAS_JUNK)
        s_process.status |= OUTPUT_NEEDS_NEW_FILE;

    /* Check the PNG signature and datastream flags. */
    if (!(s_process.status & INPUT_HAS_PNG_SIGNATURE))
        s_process.status |= OUTPUT_NEEDS_NEW_FILE;
    if (s_process.status & INPUT_HAS_PNG_DATASTREAM)
    {
        if (s_options.nz && (s_process.status & OUTPUT_NEEDS_NEW_IDAT))
        {
            usr_printf(
                "IDAT recoding is necessary, but is disabled by the user.\n");
            opng_throw_error("Can't continue");
        }
    }
    else
        s_process.status |= OUTPUT_NEEDS_NEW_IDAT;

    /* Check the digital signature flag. */
    if (s_process.status & INPUT_HAS_DIGITAL_SIGNATURE)
    {
        usr_printf("Digital signature found in input.");
        if (s_options.force)
        {
            usr_printf(" Erasing...\n");
            s_process.status |= OUTPUT_NEEDS_NEW_FILE;
        }
        else
        {
            usr_printf(" Rerun " PROGRAM_NAME " with -force enabled.\n");
            opng_throw_error("Can't optimize digitally-signed files");
        }
    }

    /* Check the multi-image flag. */
    if (s_process.status & INPUT_HAS_MULTIPLE_IMAGES)
    {
        if (!s_options.snip && !(s_process.status & INPUT_IS_PNG_FILE))
        {
            usr_printf("Conversion to PNG requires snipping. "
                       "Rerun " PROGRAM_NAME " with -snip enabled.\n");
            opng_throw_error("Incompatible input format");
        }
    }
    if (s_options.snip && (s_process.status & INPUT_HAS_APNG))
        s_process.status |= OUTPUT_NEEDS_NEW_FILE;

    /* Check the stripped-data flag. */
    if (s_process.status & INPUT_HAS_STRIPPED_DATA)
        usr_printf("Stripping metadata...\n");

    /* Initialize the output file name. */
    outfile_name = NULL;
    if (!(s_process.status & INPUT_IS_PNG_FILE))
    {
        if (opng_path_replace_ext(name_buf, sizeof(name_buf),
                                  infile_name_local, ".png") == NULL)
            opng_throw_error("Can't create the output file (name too long)");
        outfile_name = name_buf;
    }
    if (s_options.out_name != NULL)
    {
        /* Override the old name. */
        outfile_name = s_options.out_name;
    }
    if (s_options.dir_name != NULL)
    {
        const char *tmp_name;
        if (outfile_name != NULL)
        {
            strcpy(tmp_buf, outfile_name);
            tmp_name = tmp_buf;
        }
        else
            tmp_name = infile_name_local;
        if (opng_path_replace_dir(name_buf, sizeof(name_buf),
                                  tmp_name, s_options.dir_name) == NULL)
            opng_throw_error("Can't create the output file (name too long)");
        outfile_name = name_buf;
    }
    if (outfile_name == NULL)
    {
        outfile_name = infile_name_local;
        new_outfile = 0;
    }
    else
    {
        int test_eq = opng_os_test_file_equiv(infile_name_local, outfile_name);
        if (test_eq >= 0)
        {
            /* We know, from the underlying OS, if the two paths are pointing
             * to the same file (test_eq == 1), or not (test_eq == 0).
             */
            new_outfile = (test_eq == 0);
        }
        else
        {
            /* We cannot know whether the two paths point to the same file.
             * Do a path name comparison as a crude backup strategy.
             */
            new_outfile = (strcmp(infile_name_local, outfile_name) != 0);
        }
    }

    /* Initialize the backup file name. */
    bakfile_name = tmp_buf;
    if (new_outfile)
    {
        if (opng_path_make_backup(tmp_buf, sizeof(tmp_buf),
                                  outfile_name) == NULL)
            bakfile_name = NULL;
    }
    else
    {
        if (opng_path_make_backup(tmp_buf, sizeof(tmp_buf),
                                  infile_name_local) == NULL)
            bakfile_name = NULL;
    }
    /* Check the name even in simulation mode, to ensure a uniform behavior. */
    if (bakfile_name == NULL)
        opng_throw_error("Can't create backup file (name too long)");
    /* Check the backup file before engaging in lengthy trials. */
    if (!s_options.simulate &&
        opng_os_test_file_access(outfile_name, "e") == 0)
    {
        if (!s_options.backup && !s_options.clobber && new_outfile)
        {
            usr_printf("The output file exists. "
                       "Rerun " PROGRAM_NAME " with -backup enabled.\n");
            opng_throw_error("Can't overwrite the output file");
        }
        if (opng_os_test_file_access(outfile_name, "fw") != 0 ||
            (!s_options.clobber &&
             opng_os_test_file_access(bakfile_name, "e") == 0))
        {
            usr_printf("A backup file already exists. "
                       "Rerun " PROGRAM_NAME " with -clobber enabled.\n");
            opng_throw_error("Can't back up the existing output file");
        }
    }

    /* Display the input IDAT/file sizes. */
    if (s_process.status & INPUT_HAS_PNG_DATASTREAM)
        usr_printf("Input IDAT size = %" OPNG_FSIZE_PRIu " bytes\n",
                   s_process.in_idat_size);
    usr_printf("Input file size = %" OPNG_FSIZE_PRIu " bytes\n",
               s_process.in_file_size);

    /* Find the best parameters and see if it's worth recompressing. */
    if (!s_options.nz || (s_process.status & OUTPUT_NEEDS_NEW_IDAT))
    {
        opng_init_iterations();
        opng_iterate();
        opng_finish_iterations();
    }
    if (s_process.status & OUTPUT_NEEDS_NEW_IDAT)
    {
        s_process.status |= OUTPUT_NEEDS_NEW_FILE;
        opng_check_idat_size(s_process.best_idat_size);
    }

    /* Stop here? */
    if (!(s_process.status & OUTPUT_NEEDS_NEW_FILE))
    {
        usr_printf("\n%s is already optimized.\n", infile_name_local);
        if (!new_outfile)
            return;
    }
    if (s_options.simulate)
    {
        usr_printf("\nNo output: simulation mode.\n");
        return;
    }

    /* Make room for the output file. */
    if (new_outfile)
    {
        usr_printf("\nOutput file: %s\n", outfile_name);
        if (s_options.dir_name != NULL)
            opng_os_create_dir(s_options.dir_name);
        has_backup = 0;
        if (opng_os_test_file_access(outfile_name, "e") == 0)
        {
            if (opng_os_rename(outfile_name, bakfile_name,
                               s_options.clobber) != 0)
                opng_throw_error("Can't back up the output file");
            has_backup = 1;
        }
    }
    else
    {
        if (opng_os_rename(infile_name_local, bakfile_name,
                           s_options.clobber) != 0)
            opng_throw_error("Can't back up the input file");
        has_backup = 1;
    }

    outfile = fopen(outfile_name, "wb");
    Try
    {
        if (outfile == NULL)
            opng_throw_error("Can't open the output file");
        if (s_process.status & OUTPUT_NEEDS_NEW_IDAT)
        {
            /* Write a brand new PNG datastream to the output. */
            opng_write_file(outfile,
                            s_process.best_compr_level,
                            s_process.best_mem_level,
                            s_process.best_strategy,
                            s_process.best_filter);
        }
        else
        {
            /* Copy the input PNG datastream to the output. */
            infile = fopen(new_outfile ? infile_name_local : bakfile_name,
                           "rb");
            if (infile == NULL)
                opng_throw_error("Can't reopen the input file");
            Try
            {
                if (s_process.in_datastream_offset > 0 &&
                    opng_fseeko(infile, s_process.in_datastream_offset,
                                SEEK_SET) != 0)
                    opng_throw_error("Can't reposition the input file");
                s_process.best_idat_size = s_process.in_idat_size;
                opng_copy_file(infile, outfile);
            }
            Catch (status)
            {
                OPNG_ENSURE(status != OPNG_STATUS_OK,
                            "opng_copy_file should throw errors only");
            }
            fclose(infile);  /* finally */
            if (status != OPNG_STATUS_OK)
                Throw status;  /* rethrow */
        }
    }
    Catch (status)
    {
        if (outfile != NULL)
            fclose(outfile);
        /* Restore the original input file and rethrow the exception. */
        if (has_backup)
        {
            if (opng_os_rename(bakfile_name,
                               new_outfile ? outfile_name : infile_name_local,
                               1) != 0)
                opng_print_warning(
                    "Can't recover the original file from backup");
        }
        else
        {
            OPNG_ENSURE(new_outfile,
                        "Overwrote input with no temporary backup");
            if (opng_os_unlink(outfile_name) != 0)
                opng_print_warning("Can't remove the broken output file");
        }
        Throw status;  /* rethrow */
    }
    fclose(outfile);

    /* Preserve file attributes (e.g. ownership, access rights, time stamps)
     * on request, if possible.
     */
    if (s_options.preserve)
        opng_os_copy_file_attr(new_outfile ? infile_name_local : bakfile_name,
                               outfile_name);

    /* Remove the backup file if it is not needed. */
    if (!s_options.backup && !new_outfile)
    {
        if (opng_os_unlink(bakfile_name) != 0)
            opng_print_warning("Can't remove the backup file");
    }

    /* Display the output IDAT/file sizes. */
    usr_printf("\nOutput IDAT size = %" OPNG_FSIZE_PRIu " bytes",
               s_process.out_idat_size);
    if (s_process.status & INPUT_HAS_PNG_DATASTREAM)
    {
        usr_printf(" (");
        opng_print_fsize_difference(s_process.in_idat_size,
                                    s_process.out_idat_size, 0);
        usr_printf(")");
    }
    usr_printf("\nOutput file size = %" OPNG_FSIZE_PRIu " bytes (",
               s_process.out_file_size);
    opng_print_fsize_difference(s_process.in_file_size,
                                s_process.out_file_size, 1);
    usr_printf(")\n");
}

/*
 * Engine initialization.
 */
int
opng_initialize(const struct opng_options *init_options,
                const struct opng_ui *init_ui)
{
    /* Initialize and check the validity of the user interface callbacks. */
    usr_printf = init_ui->printf_fn;
    usr_print_cntrl = init_ui->print_cntrl_fn;
    usr_progress = init_ui->progress_fn;
    usr_panic = init_ui->panic_fn;
    if (usr_printf == NULL ||
        usr_print_cntrl == NULL ||
        usr_progress == NULL ||
        usr_panic == NULL)
        return -1;

    /* Initialize and adjust the user options. */
    s_options = *init_options;
    if (s_options.optim_level == 0)
    {
        s_options.nb = s_options.nc = s_options.np = 1;
        s_options.nz = 1;
    }

    /* Start the engine. */
    memset(&s_summary, 0, sizeof(s_summary));
    s_engine.started = 1;
    return 0;
}

/*
 * Engine execution.
 */
int
opng_optimize(const char *infile_name)
{
    opng_status_t status;
    volatile int result;  /* volatile not needed, but keeps compilers happy */

    OPNG_ENSURE(s_engine.started, "The OptiPNG engine is not running");

    usr_printf("** Processing: %s\n", infile_name);
    ++s_summary.file_count;
    opng_clear_image_info();
    Try
    {
        opng_optimize_impl(infile_name);
        if (s_process.status & INPUT_HAS_ERRORS)
        {
            ++s_summary.err_count;
            ++s_summary.fix_count;
        }
        if (s_process.status & INPUT_HAS_MULTIPLE_IMAGES)
        {
            if (s_options.snip)
                ++s_summary.snip_count;
        }
        result = 0;
    }
    Catch (status)
    {
        OPNG_ENSURE(status != OPNG_STATUS_OK,
                    "opng_optimize_impl should throw errors only");
        ++s_summary.err_count;
        result = -1;
    }
    opng_destroy_image_info();
    usr_printf("\n");
    return result;
}

/*
 * Engine finalization.
 */
int
opng_finalize(void)
{
    /* Print the status report. */
    if (s_options.verbose ||
        s_summary.snip_count > 0 ||
        s_summary.err_count > 0)
    {
        usr_printf("** Status report\n");
        usr_printf("%u file(s) have been processed.\n", s_summary.file_count);
        if (s_summary.snip_count > 0)
        {
            usr_printf("%u multi-image file(s) have been snipped.\n",
                       s_summary.snip_count);
        }
        if (s_summary.err_count > 0)
        {
            usr_printf("%u error(s) have been encountered.\n",
                       s_summary.err_count);
            if (s_summary.fix_count > 0)
                usr_printf("%u erroneous file(s) have been fixed.\n",
                           s_summary.fix_count);
        }
    }

    /* Stop the engine. */
    s_engine.started = 0;
    return 0;
}
