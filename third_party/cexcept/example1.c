/*===
cexcept: example1.c

An example program that demonstrates how to use the cexcept interface.
This program is single-threaded and uses a global exception context.

See example2.c for a demonstration of nested Try blocks, avoidance of
global variables by passing the context in function arguments, and the
use of a polymorphic exception type.

Use, modification and distribution are subject to the zlib license.
See the accompanying LICENSE.md file for copyright information, or visit
https://opensource.org/license/zlib

===*/


#include <stdio.h>
#include <stdlib.h>


/* The following declarations would normally go in a separate .h file: */

#include "cexcept.h"
define_exception_type(int);
extern struct exception_context the_exception_context[1];

/* End of separate .h file. */


void demo_throw(int fail)
{
  fprintf(stderr, "enter demo_throw(%d)\n", fail);
  if (fail) Throw 42;
  fprintf(stderr, "return from demo_throw(%d)\n", fail);
}


void foo(int fail)
{
  fprintf(stderr, "enter foo(%d)\n", fail);
  demo_throw(fail);
  fprintf(stderr, "return from foo(%d)\n", fail);
}


/* Globally accessible storage for the exception context: */

struct exception_context the_exception_context[1];


int main()
{
  int e;

  Try {
    foo(0);
    foo(1);
    foo(2);
  }
  Catch (e) fprintf(stderr, "exception %d\n", e);

  Try foo(3);
  Catch_anonymous fprintf(stderr, "anonymous exception\n");

  return EXIT_SUCCESS;
}
