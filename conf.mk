include tp/conf.mk

BPFTOOL_SRC = bpftool
LIBBPF_SRC  = libbpf

CC      = clang
CFLAGS  = -Wall -Wextra -Werror -Wno-unused-parameter -I vmlinux
# Set the architecture for vmlinux
CFLAGS += -D__TARGET_ARCH_$(ARCH)
# This makes it easier for the verifier to verify the program
CFLAGS += -O2
# Generate BTF
CFLAGS  += -g
LDFLAGS  = -l elf -l z
LDFLAGS += $(LIBBPF_SRC)/src/libbpf.a

ARCH = $(shell uname -m)
