# BPF toolchain installation on Arch Linux

## Install some packages

```
# pacman -S --needed \
	base-devel xmlto kmod inetutils bc libelf git \
	make gcc bison flex llvm clang \
	openssl ncurses pkgconf libcap libmnl lib32-glibc \
	graphviz
```

## Compile kernel

```
$ git clone https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git
$ cd linux
$ git checkout linux-5.3.y

$ make mrproper
$ zcat /proc/config.gz > .config
$ make localmodconfig
$ make menuconfig	/* change localversion */
$ nvim .config
----
	CONFIG_BPF=y
	CONFIG_BPF_SYSCALL=y
	CONFIG_BPF_JIT=y
	CONFIG_BPF_EVENTS=y
	CONFIG_CGROUP_BPF=y
	CONFIG_LWTUNNEL_BPF=y
	CONFIG_HAVE_EBPF_JIT=y
	CONFIG_NET_CLS_ACT=y

/* We always want to use JIT for performance, so either this option should be on,
 * or this should be done: "sudo echo 1 > /proc/sys/net/core/bpf_jit_enable" 
 */
	CONFIG_BPF_JIT_ALWAYS_ON=y

	CONFIG_NET_SCH_INGRESS=m
	CONFIG_NET_CLS_BPF=m
	CONFIG_TEST_BPF=m	/* really not that needed */
----
$ make -j8

# make modules_install

# cp -v arch/x86_64/boot/bzImage /boot/vmlinuz-linux-bpf-tc

# cp -v /etc/mkinitcpio.d/linux.preset /etc/mkinitcpio.d/linux-bpf-tc.preset
# nvim /etc/mkinitcpio.d/linux-bpf-tc.preset
----
	ALL_kver="/boot/vmlinuz-linux-bpf-tc"
	default_image="/boot/initramfs-linux-bpf-tc.img"
	fallback_image="/boot/initramfs-linux-bpf-tc-fallback.img"
----
# mkinitcpio -p linux-bpf-tc

# cp System.map /boot/System.map-linux-bpf-tc
# ln -sf /boot/System.map-linux-bpf-tc /boot/System.map

# nvim /etc/default/grub
# grub-mkconfig -o /boot/grub/grub.cfg
```

## Boot into new kernel and verify setup

```
$ cd linux/tools/testing/selftests/bpf
$ nvim Makefile
----
151:	CLANG_FLAGS += -fno-stack-protector
----
$ make
# ./test_verifier

# make run_tests
```

## Install bpftool

```
$ cd linux/tools/bpf/bpftool/
$ make
# make install
```
`bpftool` correlates calls to helper functions or BPF to BPF calls through `kallsyms`.
Therefore, make sure that JITed BPF programs are exposed to kallsyms (`bpf_jit_kallsyms`)
and that kallsyms addresses are not obfuscated (calls are otherwise shown as `call bpf_unspec#0`):
```
# echo 0 > /proc/sys/kernel/kptr_restrict
# echo 1 > /proc/sys/net/core/bpf_jit_kallsyms
```

## Check eBPF assembly
```
$ llvm-objdump -S --no-show-raw-insn obj/tc_test.o.g
```

