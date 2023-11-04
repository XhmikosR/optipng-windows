/*
 * wildargs.c
 * Automatic command-line wildcard expansion for environments that
 * are not based on the Un*x shell.
 *
 * Copyright (C) 2003-2022 Cosmin Truta.
 *
 * This software is distributed under the zlib license.
 * Please see the accompanying LICENSE file.
 */

/*
 * Dummy header inclusion for a guaranteed non-empty translation unit.
 */
#include <stddef.h>

/*
 * Compiler and platform detection.
 */
#if defined _WIN32 || defined __WIN32__ || defined __NT__
#if defined _MSC_VER && (_MSC_VER >= 1900)
#define WILDARGS_WINDOWS_UCRT
#elif defined _MSC_VER && (_MSC_VER < 1900)
#define WILDARGS_WINDOWS_MSVCRT
#elif defined __MINGW32__ || defined __MINGW64__
#define WILDARGS_WINDOWS_MSVCRT
#elif defined __BORLANDC__
#define WILDARGS_WINDOWS_BORLANDC
#endif
#endif  /* _WIN32 || __WIN32__ || __NT__ */

/*
 * Automatic wildargs expansion for the modern Microsoft Visual C++ CRT (UCRT).
 * The implementation is inspired from the Microsoft UCRT source code.
 */
#if defined WILDARGS_WINDOWS_UCRT
#include <vcruntime_startup.h>
_crt_argv_mode __CRTDECL _get_startup_argv_mode()
{
    return _crt_argv_expanded_arguments;
}
#endif

/*
 * Automatic wildargs expansion for the older Microsoft Visual C++ CRT (MSVCRT)
 * and MinGW.
 * The implementation is inspired from MinGW32 by Colin Peters.
 */
#if defined WILDARGS_WINDOWS_MSVCRT
int _dowildcard = 1;
#endif

/*
 * Automatic wildargs expansion for Borland C++ for Windows.
 * The implementation is inspired from BMP2PNG by MIYASAKA Masaru.
 */
#if defined WILDARGS_WINDOWS_BORLANDC
#include <wildargs.h>
typedef void _RTLENTRY (* _RTLENTRY _argv_expand_fn)(char *, _PFN_ADDARG);
typedef void _RTLENTRY (* _RTLENTRY _wargv_expand_fn)(wchar_t *, _PFN_ADDARG);
_argv_expand_fn _argv_expand_ptr = _expand_wild;
_wargv_expand_fn _wargv_expand_ptr = _wexpand_wild;
#endif
