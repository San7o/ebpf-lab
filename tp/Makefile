BPFTOOL_SRC = ../bpftool
LIBBPF_SRC  = ../libbpf

BPF  = tp.bpf.o
SKEL = tp.skel.h
OBJ  = tp.o
OUT  = tp

CC      = clang
CFLAGS  = -Wall -Wextra -Werror -Wno-unused-parameter -I ../vmlinux
# Set the architecture for vmlinux
CFLAGS += -D__TARGET_ARCH_$(ARCH)
# This makes it easier for the verifier to verify the program
CFLAGS += -O2
# Generate BTF
CFLAGS  += -g
LDFLAGS  = -l elf -l z
LDFLAGS += $(LIBBPF_SRC)/src/libbpf.a

ARCH = $(shell uname -m)

all: libbpf bpftool bpf loader

libbpf: $(LIBBPF_SRC)/src/libbpf.a

bpftool: $(BPFTOOL_SRC)/src/bpftool

.PHONY: bpf
bpf: $(BPF)

.PHONY: loader
loader: $(OUT)

.PHONY: skel
skel: $(SKEL)

$(LIBBPF_SRC)/src/libbpf.a:
	make -C $(LIBBPF_SRC)/src -j$(shell nproc) BUILD_STATIC_ONLY=y

$(BPFTOOL_SRC)/src/bpftool:
	make -C $(BPFTOOL_SRC)/src -j$(shell nproc)

$(OUT): $(SKEL) $(OBJ)
	$(CC) $(OBJ) $(LDFLAGS) -o $(OUT)

$(SKEL): $(BPF)
	$(BPFTOOL_SRC)/src/bpftool gen skeleton $< > $@

%.bpf.o: %.bpf.c
	$(CC) $(CFLAGS) -target bpf -c $^ -o $@

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@


