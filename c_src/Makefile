# Makefile — builds priv/itb_nif.so, the NIF shim of the ITB Erlang
# binding. Invoked by the rebar3 compile pre-hook (see ../rebar.config)
# and usable standalone.
#
# The shim compiles against the C binding's public header
# (bindings/c/include/itb.h), links its static archive
# (bindings/c/build/libitb_c.a) plus libitb.so from the repo dist dir
# (-litb with an embedded RPATH, so LD_LIBRARY_PATH is unnecessary at
# runtime).
#
# Variables (override on the command line):
#   CC                C compiler                       (default: cc)
#   ERTS_INCLUDE_DIR  erl_nif.h location               (default: from erl)
#   ITB_DIST          path to libitb.so dir            (default: repo dist)

CURDIR_ABS := $(abspath .)
BASEDIR    := $(abspath $(CURDIR_ABS)/..)
REPO_ROOT  := $(abspath $(BASEDIR)/../..)
C_BINDING  := $(REPO_ROOT)/bindings/c
ITB_DIST   ?= $(REPO_ROOT)/dist/linux-amd64

ERTS_INCLUDE_DIR ?= $(shell erl -noshell -eval \
    'io:format("~ts/erts-~ts/include", [code:root_dir(), erlang:system_info(version)]), halt().')

CC    ?= cc
WARN   = -Wall -Wextra -Werror
CFLAGS = -std=c11 -O2 -g $(WARN) -fPIC \
         -I$(ERTS_INCLUDE_DIR) -I$(C_BINDING)/include
LDFLAGS = -L$(ITB_DIST) -Wl,-rpath,$(ITB_DIST)

PRIV = $(BASEDIR)/priv
NIF  = $(PRIV)/itb_nif.so

all: $(NIF)

$(NIF): itb_nif.c $(C_BINDING)/include/itb.h $(C_BINDING)/build/libitb_c.a
	@mkdir -p $(PRIV)
	$(CC) $(CFLAGS) -shared itb_nif.c $(C_BINDING)/build/libitb_c.a \
	    -o $@ $(LDFLAGS) -litb

# The C binding's static archive; built with -fPIC by its own Makefile
# so it links cleanly into this shared object.
$(C_BINDING)/build/libitb_c.a:
	$(MAKE) -C $(C_BINDING) build/libitb_c.a

clean:
	rm -f $(NIF)

.PHONY: all clean
