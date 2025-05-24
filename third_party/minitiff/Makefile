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

MINITIFF_LIB = libminitiff.a
MINITIFF_OBJS = tiffread.o tiffutil.o #tiffwrite.o
TIFF2PNM = tiff2pnm$(EXEEXT)
TIFF2PNM_OBJS = tiff2pnm.o

.PHONY: all
all: $(MINITIFF_LIB) $(TIFF2PNM)

.PHONY: test
test: $(TIFF2PNM)
	@echo TODO: run $(TIFF2PNM)

.PHONY: check
check: test

.c.o:
	$(CC) -c $(CPPFLAGS) $(CFLAGS) -o $@ $<

$(MINITIFF_LIB): $(MINITIFF_OBJS)
	$(AR) $(ARFLAGS) $@ $(MINITIFF_OBJS)
	$(RANLIB) $@

$(TIFF2PNM): $(TIFF2PNM_OBJS) $(MINITIFF_LIB)
	$(LD) $(LDFLAGS) -o $@ $(TIFF2PNM_OBJS) $(MINITIFF_LIB) $(LIBS)

tiffread.o: $(srcdir)/tiffread.c $(srcdir)/minitiff.h
	$(CC) -c $(CPPFLAGS) $(CFLAGS) -o $@ $<

tiffutil.o: $(srcdir)/tiffutil.c $(srcdir)/minitiff.h
	$(CC) -c $(CPPFLAGS) $(CFLAGS) -o $@ $<

#tiffwrite.o: $(srcdir)/tiffwrite.c $(srcdir)/minitiff.h
#	$(CC) -c $(CPPFLAGS) $(CFLAGS) -o $@ $<

tiff2pnm.o: $(srcdir)/testprog/tiff2pnm.c $(srcdir)/minitiff.h
	$(CC) -c -I$(srcdir) $(CPPFLAGS) $(CFLAGS) -o $@ $<

.PHONY: clean
clean:
	-$(RM_F) $(MINITIFF_LIB) $(MINITIFF_OBJS)
	-$(RM_F) $(TIFF2PNM) $(TIFF2PNM_OBJS)

.PHONY: distclean
distclean: clean
