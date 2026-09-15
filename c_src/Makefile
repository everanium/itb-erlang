# Makefile — builds priv/libitb3_nif.so, the NIF shim of the ITB Erlang
# binding. Invoked by the rebar3 compile pre-hook (see ../rebar.config)
# and usable standalone.
#
# The shim compiles against the C binding's public header
# (bindings/c/include/itb3.h), links its static archive
# (bindings/c/build/libitb3_c.a) plus libitb3.so from the repo dist dir
# (-litb3 with an embedded RPATH, so LD_LIBRARY_PATH is unnecessary at
# runtime).
#
# Variables (override on the command line):
#   CC                C compiler                       (default: cc)
#   ERTS_INCLUDE_DIR  erl_nif.h location               (default: from erl)
#   ITB_DIST          path to libitb3.so dir            (default: repo dist)

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
NIF  = $(PRIV)/libitb3_nif.so

all: $(NIF)

$(NIF): libitb3_nif.c $(C_BINDING)/include/itb3.h $(C_BINDING)/build/libitb3_c.a
	@mkdir -p $(PRIV)
	$(CC) $(CFLAGS) -shared libitb3_nif.c $(C_BINDING)/build/libitb3_c.a \
	    -o $@ $(LDFLAGS) -litb3

# The C binding's static archive; built with -fPIC by its own Makefile
# so it links cleanly into this shared object.
$(C_BINDING)/build/libitb3_c.a:
	$(MAKE) -C $(C_BINDING) build/libitb3_c.a

clean:
	rm -f $(NIF)

.PHONY: all clean
