CC = clang
CFLAGS = -O2 -Wall -Wextra -Werror -I$(IDIR)

IDIR = ./include
LDIR = ./lib64
PROGDIR = ./prog
OBJDIR = ./obj

# this Makefile will basically compile all programs in ./prog directory
PROG := $(shell ls ./prog)
OBJ := $(patsubst %.c,$(OBJDIR)/%.o,$(PROG))
DEBUG ?= no

# program parameters for tc loader
TC_PROG ?= $(OBJDIR)/tc_prog.o
TC_SEC ?= main
ETH_DEV ?= ens34

# custom loader and libs for it
LOADER = kpload
LIBBPF = $(LDIR)/libbpf.a
LIBS = -lelf -lz

PHONY := all
all: prog loader

PHONY += prog
prog: $(OBJ)

PHONY += loader
loader: $(LOADER)

$(OBJDIR)/%.o : $(PROGDIR)/%.c
	@if [ ! -d obj ]; then mkdir obj; fi
	$(CC) $(CFLAGS) -target bpf -o $@ -c $^
	@if [ "$(DEBUG)" = "yes" ]; then $(CC) $(CFLAGS) -target bpf -g -o $@.g -c $^; fi

$(LOADER) : $(LOADER).c $(LIBBPF)
	$(CC) $(CFLAGS) $(LIBS) -o $@ $^

PHONY += tc_reattach
tc_reattach: tc_detach tc_attach

PHONY += tc_setup
tc_setup:
	sudo tc qdisc add dev $(ETH_DEV) clsact

PHONY += tc_attach
tc_attach:
	sudo tc filter add dev $(ETH_DEV) ingress bpf da obj $(TC_PROG) sec $(TC_SEC)

PHONY += tc_detach
tc_detach:
	sudo tc filter del dev $(ETH_DEV) ingress

PHONY += tc_clean
tc_clean:
	sudo tc qdisc del dev $(ETH_DEV) clsact

PHONY += clean
clean:
	@rm -rf $(OBJDIR) $(LOADER)

PHONY += distclean
distclean: clean
	@rm -f cscope*.out

PHONY += cscope
cscope:
	@find ./ -name "*.c" -o -name "*.h" > cscope.files
	@cscope -b -q
	@rm cscope.files

.PHONY: $(PHONY)

