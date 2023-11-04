Name: zlib
Summary: A general-purpose data compression library
Authors: Jean-loup Gailly and Mark Adler
Version: 1.3
Modified version: 1.3-optipng
License: zlib
URL: http://zlib.net/

Modifications:
 - Ensured that ZLIB_CONST is always defined and that the const-correct
   version of the zlib API is always enabled, regardless of the external
   build options.
 - Defined NO_GZCOMPRESS and NO_GZIP in order to compile out the unused
   gzip-processing code.
 - Set TOO_FAR to the largest possible value (i.e., 32768) to increase
   the probability of producing better-compressed deflate streams.
 - Changed ZLIB_VERSION to "1.3-optipng"; changed ZLIB_VERNUM to 0x130f;
   changed ZLIB_VER_SUBREVISION to 15.
