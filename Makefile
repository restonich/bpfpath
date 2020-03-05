CC = clang
CFLAGS = -O2 -Wall -Wextra -Werror -target bpf -I$(IDIR)

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

# custom loader
LOADER = bpf_loader
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
	$(CC) $(CFLAGS) -o $@ -c $^
	@if [ "$(DEBUG)" = "yes" ]; then $(CC) -g $(CFLAGS) -o $@.g -c $^; fi

$(LOADER) : $(LOADER).c $(LIBBPF)
	clang -O2 -Wall -Wextra -Werror -I$(IDIR) -o $@ $^ $(LIBS)

PHONY += tc_reattach
tc_reattach: tc_detach tc_attach

PHONY += tc_attach
tc_attach:
	sudo tc qdisc add dev $(ETH_DEV) clsact
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
	@rm -f cscope*.out cscope.files

PHONY += cscope
cscope:
	@find ./ -name "*.c" -o -name "*.h" > cscope.files
	@cscope -b -q

.PHONY: $(PHONY)

