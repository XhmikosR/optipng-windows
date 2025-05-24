# cexcept

## Change Log

### 2025-Apr-07-Mon

 - cexcept 2.0.2-optipng --> 2.99-optipng

    * Relicensed the package from the cexcept license to the zlib license.
    * Converted the documentation format from plain text to Markdown.
    * Reorganized the structure of the source tree.

### 2023-Nov-02-Thu

 - example2.c 2.0.0 --> 2.0.0+

    * Added a test for empty Try and Catch blocks.
    * Added BSD-style FALLTHROUGH and NOTREACHED comments where applicable.

### 2022-Nov-20-Sun

 - cexcept.h 2.0.1-optipng --> 2.0.2-optipng

    * Improved the workaround against aggressive optimizing compilers
      that might clobber the exception__prev pointer. Instead of making
      this pointer volatile, we are boxing it inside a one-element array.

### 2011-Jul-22-Fri

 - cexcept.h 2.0.1 --> 2.0.1-optipng

    * Made exception__prev volatile to avoid "variable might be clobbered
      by longjmp" warnings when a function contains multiple Try blocks.

### 2008-Jul-23-Wed

 - cexcept.h 2.0.0 --> 2.0.1

    * Clarified the license.
    * Reworded the introductory comments.
    * Bug fix:  The statement following Try could not be an if-statement
      (without else); the Catch would then be parsed wrong.
    * Quieted a new warning in gcc 4.2.

 - README 2.0.0 --> 2.0.1

    * Reworded the license to agree with cexcept.h.
    * Updated the URLs.

### 2001-Jul-12-Thu

 - cexcept.h 1.0.0 --> 2.0.0

    * The documentation had neglected to mention that the Catch
      expression was evaluated before the Try clause was executed.
      Rather than document this unintuitive behavior, we have changed
      the interface so that the Catch expression is not evaluated unless
      and until an exception is caught.  This change will not affect
      applications that never used Catch expressions with side effects.
    * The implementation had been technically incorrect because it
      modified the object named by the Catch expression between the
      setjmp and longjmp calls, even though it might be a non-volatile
      automatic object (which it was in example.c).  The problem (which
      affected no known compilers) has been corrected by performing two
      copies: first into volatile temporary storage before the longjmp,
      then into the Catch expression after the longjmp.
    * The requirement that the Catch expression have the "exact same
      type" that was passed to define_exception_type() has been slightly
      relaxed to disregard type qualifiers.
    * In the license, "no guarantees about the correctness of this file"
      has been changed to "no guarantees regarding this file".
    * Notes have been added that "real" exceptions are not supported, and
      the size of the exception type has performance implications.

 - rationale 1.0.0 --> 2.0.0

    * Removed the obsolete question about why the Catch expression is
      always evaluated.
    * Updated the answer to the question about the type of the Catch
      expression, to correspond to the new implementation.
    * Added a question about why two copies are necessary.
    * Added a question about why "real" exceptions cannot be caught.

 - example.c 1.0.0 --> example1.c 2.0.0

 - example2.c 1.0.0 --> 2.0.0

    * Renamed example.c to example1.c.
    * Changed the version number to agree with cexcept.h in the first
      two places (2.0.*).

 - README 1.0.0 --> 2.0.0

    * Reworded the license to agree with cexcept.h.
    * Changed the version number to agree with cexcept.h in the first
      two places (2.0.*).

### 2000-Jun-21-Wed

 - cexcept.h 0.6.1 --> 1.0.0

    * Changed the version number to indicate stability.
    * Changed "an lvalue" to "a modifiable lvalue" to agree with the
      language in the ISO C Standard.
    * Added hints about dealing with the inability to return from a Try
      clause, and with automatic variables modified within a Try clause.
    * Clarified the restriction on Throw'ing a comma-expression.

 - example.c 0.6.0 --> 1.0.0

    * Changed the version number to agree with cexcept.h in the first
      two places (1.0.*).

 - example2.c 0.6.0 --> 1.0.0

    * Changed the version number to agree with cexcept.h in the first
      two places (1.0.*).

 - rationale 0.6.1 --> 1.0.0

    * Changed the version number to agree with cexcept.h in the first
      two places (1.0.*).

 - README 0.6.3 --> 1.0.0

    * Changed the version number to agree with cexcept.h in the first
      two places (1.0.*).

### 2000-Apr-22-Sat

 - cexcept.h 0.6.0 --> 0.6.1

    * Clarified that the wrapper .h file is needed only when there are
      multiple .c files.

### 2000-Apr-08-Sat

 - rationale 0.6.0 --> 0.6.1

    * Added rationale for disallowing jumping in/out of Try clauses.
    * Expanded the discussion of finally clauses.
    * Added rationale for the lack of expressionless Throw.

### 2000-Apr-07-Fri

 - Created README, which incorporates changelog.

 - cexcept.h amc.0.5.3 --> 0.6.0

    * The expression passed to Catch must now have exactly the same type
      passed to define_exception_type(), and it is always evaluated
      exactly once, regardless of whether an exception is caught.
    * Added Catch_anonymous.
    * Changed init_exception_context() to take an argument, and to be
      optional for statically allocated contexts.
    * Clarified allowable exception types, added examples.
    * Clarified the restrictions on jumping in Try/Catch statements.
    * Reworded some other parts of the documentation.

 - cexcept-example.c amc.0.5.0 --> example.c 0.6.0

    * Now uses the 0.6.* interface, and demonstrates Catch_anonymous.

 - cexcept-example2.c amc.0.5.0 --> example2.c 0.6.0

    * Now uses the 0.6.* interface.

 - cexcept-rationale amc.0.5.1 --> rationale 0.6.0

    * Added rationale for the new Catch expression semantics.

### 2000-Apr-01-Fri

 - cexcept.h amc.0.5.2 --> amc.0.5.3

    * Eliminated a compiler warning about an uninitialized variable.
    * Improved the documentation of allowable exception types.
    * Added advice about using a macro for the_exception_context, and
      changed the example accordingly.
    * Improved the documentation regarding jumping out of Try and Catch.

Earlier changes were not logged.
