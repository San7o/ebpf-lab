ifeq (${PROG_XDP},1)
	include xdp/conf.mk
else ifeq (${PROG_TC},1)
	include tc/conf.mk
else ifeq (${PROG_SCX},1)
	include sched_ext/conf.mk
else ifeq (${PROG_LSM},1)
	include lsm/conf.mk
else ifeq (${PROG_TASK_ITER},1)
	include task_iter/conf.mk
else
	# Default
	include tp/conf.mk
endif

BPFTOOL_SRC = bpftool
LIBBPF_SRC  = libbpf

CC      = clang
CFLAGS  = -Wall -Wextra -Werror -I vmlinux
CFLAGS += -Wno-unused-variable
CFLAGS += -Wno-unused-parameter
CFLAGS += -Wno-visibility
# Set the architecture for vmlinux
CFLAGS += -D__TARGET_ARCH_$(ARCH)
# This makes it easier for the verifier to verify the program
CFLAGS += -O2
# Generate BTF
CFLAGS  += -g
LDFLAGS  = -l elf -l z
LDFLAGS += $(LIBBPF_SRC)/src/libbpf.a

ARCH = $(shell uname -m)
