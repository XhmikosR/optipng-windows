Name: cexcept
Summary: Exception handling in C
Authors: Adam M. Costello and Cosmin Truta
Version: 2.0.2-optipng
Base version: 2.0.1
URL: http://www.nicemice.net/cexcept/

Changes:

 1. Made exception__prev volatile to avoid "variable might be clobbered
    by longjmp" warnings when a function contains multiple Try blocks.
 2. Improved the workaround against aggressive optimizing compilers
    that might clobber the exception__prev pointer. Instead of making
    this pointer volatile, we are boxing it inside a one-element array.

Patch: cexcept-2-0-2-optipng.diff
