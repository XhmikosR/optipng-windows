Name: cexcept
Summary: Exception handling in C
Authors: Adam M. Costello and Cosmin Truta
License: zlib
License file: LICENSE.md
Modified version: 2.99-optipng
Base version: 2.0.1
URL: https://sourceforge.net/projects/cexcept/

Modifications:
 - Made exception__prev volatile to avoid "variable might be clobbered
   by longjmp" warnings when a function contains multiple Try blocks.
 - Improved the workaround against aggressive optimizing compilers
   that might clobber the exception__prev pointer. Instead of making
   this pointer volatile, we are boxing it inside a one-element array.
 - Modified an example program (example2.c):
    * Added a test for empty Try and Catch blocks.
    * Added BSD-style FALLTHROUGH and NOTREACHED comments.
 - Relicensed the package from the cexcept license to the zlib license;
   converted the documentation format from plain text to Markdown; and
   reorganized the structure of the source tree.
