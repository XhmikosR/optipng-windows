# Generated from Makefile.in
# Preconfigured for Unix (generic)

.PRECIOUS: Makefile
.SUFFIXES: .c .o .a

srcdir = .

CC = cc
CFLAGS = -O2
CPP = $(CC) -E
CPPFLAGS =
LD = $(CC)
LDFLAGS = -s
AR = ar
ARFLAGS = cru
RANLIB = ranlib
LIBS =
RM_F = rm -f

PNMIO_LIB = libpnmio.a
PNMIO_OBJS = pnmin.o pnmout.o pnmutil.o

.PHONY: all
all: $(PNMIO_LIB)

.PHONY: test
test:
	@echo TODO: test $(PNMIO_LIB)

.PHONY: check
check: test

.c.o:
	$(CC) -c $(CPPFLAGS) $(CFLAGS) -o $@ $<

$(PNMIO_LIB): $(PNMIO_OBJS)
	$(AR) $(ARFLAGS) $@ $(PNMIO_OBJS)
	$(RANLIB) $@

pnmin.o: $(srcdir)/pnmin.c $(srcdir)/pnmio.h
	$(CC) -c $(CPPFLAGS) $(CFLAGS) -o $@ $<

pnmout.o: $(srcdir)/pnmout.c $(srcdir)/pnmio.h
	$(CC) -c $(CPPFLAGS) $(CFLAGS) -o $@ $<

pnmutil.o: $(srcdir)/pnmutil.c $(srcdir)/pnmio.h
	$(CC) -c $(CPPFLAGS) $(CFLAGS) -o $@ $<

.PHONY: clean
clean:
	-$(RM_F) $(PNMIO_LIB) $(PNMIO_OBJS)

.PHONY: distclean
distclean: clean
