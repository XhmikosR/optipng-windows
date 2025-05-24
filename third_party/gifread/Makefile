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

GIFREAD_LIB = libgifread.a
GIFREAD_OBJS = gifread.o
GIFDUMP = ./gifdump$(EXEEXT)
GIFDUMP_OBJS = gifdump.o
GIFDUMP_OUT = *.gifdump.out

.PHONY: all
all: $(GIFREAD_LIB) $(GIFDUMP)

.PHONY: test
test: $(GIFDUMP)
	$(GIFDUMP) $(srcdir)/testimg/compass.gif > compass.gifdump.out
	-@echo gifdump test ... ok

.PHONY: check
check: test

.c.o:
	$(CC) -c $(CPPFLAGS) $(CFLAGS) -o $@ $<

$(GIFREAD_LIB): $(GIFREAD_OBJS)
	$(AR) $(ARFLAGS) $@ $(GIFREAD_OBJS)
	$(RANLIB) $@

$(GIFDUMP): $(GIFDUMP_OBJS) $(GIFREAD_LIB)
	$(LD) $(LDFLAGS) -o $@ $(GIFDUMP_OBJS) $(GIFREAD_LIB) $(LIBS)

gifread.o: $(srcdir)/gifread.c $(srcdir)/gifread.h
	$(CC) -c $(CPPFLAGS) $(CFLAGS) -o $@ $<

gifdump.o: $(srcdir)/testprog/gifdump.c $(srcdir)/gifread.h
	$(CC) -c -I$(srcdir) $(CPPFLAGS) $(CFLAGS) -o $@ $<

.PHONY: clean
clean:
	-$(RM_F) $(GIFREAD_LIB) $(GIFREAD_OBJS)
	-$(RM_F) $(GIFDUMP) $(GIFDUMP_OBJS) $(GIFDUMP_OUT)

.PHONY: distclean
distclean: clean
