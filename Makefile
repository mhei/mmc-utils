CC ?= gcc
GIT_VERSION := "$(shell git describe --abbrev=6 --always --tags)"
AM_CFLAGS = -D_FILE_OFFSET_BITS=64 -D_FORTIFY_SOURCE=2 \
	    -DVERSION=\"$(GIT_VERSION)\"
CFLAGS ?= -g -O2
objects = \
	mmc.o \
	mmc_cmds.o \
	lsmmc.o \
	3rdparty/hmac_sha/hmac_sha2.o \
	3rdparty/hmac_sha/sha2.o

CHECKFLAGS = -Wall -Werror -Wuninitialized -Wundef

DEPFLAGS = -Wp,-MMD,$(@D)/.$(@F).d,-MT,$@

override CFLAGS := $(CHECKFLAGS) $(AM_CFLAGS) $(CFLAGS)

INSTALL = install
prefix ?= /usr/local
bindir = $(prefix)/bin
LIBS=
RESTORE_LIBS=
mandir = /usr/share/man

progs = mmc

# make C=1 to enable sparse - default
C ?= 1
ifeq "$(C)" "1"
	check = sparse $(CHECKFLAGS) $(AM_CFLAGS)
endif

all: $(progs)

.c.o:
ifeq "$(C)" "1"
	$(check) $<
endif
	$(CC) $(CPPFLAGS) $(CFLAGS) $(DEPFLAGS) -c $< -o $@

mmc: $(objects)
	$(CC) $(CFLAGS) -o $@ $(objects) $(LDFLAGS) $(LIBS)

manpages:
	$(MAKE) -C man

clean:
	rm -f $(progs) $(objects)
	$(MAKE) -C man clean
	$(MAKE) -C docs clean

install: $(progs)
	$(INSTALL) -m755 -d $(DESTDIR)$(bindir)
	$(INSTALL) $(progs) $(DESTDIR)$(bindir)
	$(INSTALL) -m755 -d $(DESTDIR)$(mandir)/man1
	$(INSTALL) -m 644 mmc.1 $(DESTDIR)$(mandir)/man1

-include $(foreach obj,$(objects), $(dir $(obj))/.$(notdir $(obj)).d)

.PHONY: all clean install manpages install-man

# Add this new target for building HTML documentation using docs/Makefile
html-docs:
	$(MAKE) -C docs html
