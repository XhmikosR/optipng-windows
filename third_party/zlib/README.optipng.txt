Name: zlib
Summary: A general-purpose data compression library
Authors: Jean-loup Gailly and Mark Adler
License: zlib
License file: LICENSE
Modified version: 1.3.1-optipng
Base version: 1.3.1
URL: http://zlib.net/

Modifications:
 - Ensured that ZLIB_CONST is always defined and that the const-correct
   version of the zlib API is always enabled, regardless of the external
   build options.
 - Defined NO_GZCOMPRESS and NO_GZIP in order to compile out the unused
   gzip-processing code.
 - Set TOO_FAR to the largest possible value (i.e., 32768) to increase
   the probability of producing better-compressed deflate streams.
 - Changed ZLIB_VERSION to "1.3.1-optipng"; changed ZLIB_VERNUM to 0x130f;
   changed ZLIB_VER_SUBREVISION to 15.

Patch files:
 - zlib-1.3.1-optipng.diff
