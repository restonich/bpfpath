CC = clang
CFLAGS = -O2 -Wall -Wextra -Werror -I$(IDIR)

IDIR = ./include
LDIR = ./lib64
PROGDIR = ./prog
OBJDIR = ./obj

DEBUG ?= no

# TC program
TC_PROG = tc_prog
TC_PROG_SEC = main
ETH_DEV ?= ens34

# kprobe program
KP_PROG = kp_prog
KP_SEC ?= kprobe/icmp_rcv
KP_NUM ?= 0x1
KP_NAME = $(KP_SEC:kprobe/%=%)
KP_OBJ = $(KP_NAME)_$(KP_PROG)

# custom loader and libs for it
LIBBPF = $(LDIR)/libbpf.a
LIBS = -lelf -lz
LOADER = kpload

PHONY := all
all: loader tc_prog kp_prog

PHONY += tc_prog
tc_prog: $(OBJDIR)/$(TC_PROG).o

PHONY += kp_prog
kp_prog: $(OBJDIR)/$(KP_OBJ).o

PHONY += loader
loader: $(LOADER)

$(OBJDIR)/$(TC_PROG).o : $(PROGDIR)/$(TC_PROG).c
	@if [ ! -d obj ]; then mkdir obj; fi
	$(CC) $(CFLAGS) -target bpf -o $@ -c $^
	@if [ "$(DEBUG)" = "yes" ]; then $(CC) $(CFLAGS) -target bpf -g -o $@.g -c $^; fi

$(OBJDIR)/$(KP_NAME)_$(KP_PROG).o : $(PROGDIR)/$(KP_PROG).c
	@if [ ! -d obj ]; then mkdir obj; fi
	$(CC) $(CFLAGS) -target bpf -DKP_SEC=\"$(KP_SEC)\" -DKP_NUM=$(KP_NUM) -o $@ -c $^
	@if [ "$(DEBUG)" = "yes" ]; then $(CC) $(CFLAGS) -target bpf -DKP_SEC=\"$(KP_SEC)\" -DKP_NUM=$(KP_NUM) -g -o $@.g -c $^; fi

$(LOADER) : $(LOADER).c $(LIBBPF)
	$(CC) $(CFLAGS) $(LIBS) -o $@ $^

PHONY += kp_load
kp_load : kp_prog loader
	sudo ./$(LOADER) $(OBJDIR)/$(KP_OBJ).o $(KP_NAME)

PHONY += tc_reattach
tc_reattach: tc_detach tc_attach

PHONY += tc_setup
tc_setup:
	sudo tc qdisc add dev $(ETH_DEV) clsact

PHONY += tc_attach
tc_attach:
	sudo tc filter add dev $(ETH_DEV) ingress bpf da obj $(OBJDIR)/$(TC_PROG).o sec $(TC_PROG_SEC)

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

