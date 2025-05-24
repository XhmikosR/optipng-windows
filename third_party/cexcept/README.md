# cexcept

**cexcept** (pronounced _"see except"_ in English) is a package
providing a Try/Catch/Throw exception handling interface for ANSI C
(C89 and subsequent ISO standards).  It does not attempt to handle
system exceptions like floating-point exceptions or addressing
exceptions, nor compiler-generated exceptions like C++ exceptions;
it is intended as a high-level, programmer-friendly wrapper to the
setjmp/longjmp interface.

The file cexcept.h contains the documentation and implementation of
the interface.  The other files are supporting documents.


## Copyright Information

 * Copyright (c) 2000-2025 Cosmin Truta.
 * Copyright (c) 2000-2008 Adam M. Costello.

This package is both free-as-in-speech and free-as-in-beer.
See the accompanying [LICENSE.md](LICENSE.md) file or visit
[opensource.org/license/zlib](https://opensource.org/license/zlib)


## Design Rationale

See [Rationale.md](Rationale.md)


## Change Log

See [ChangeLog.md](ChangeLog.md)
