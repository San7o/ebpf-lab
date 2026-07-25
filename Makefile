include conf.mk

all: libbpf bpftool bpf loader

.PHONY: libbpf
libbpf: $(LIBBPF_SRC)/src/libbpf.a

.PHONY: libbpf
bpftool: $(BPFTOOL_SRC)/src/bpftool

.PHONY: bpf
bpf: $(BPF)

.PHONY: loader
loader: $(OUT)

.PHONY: skel
skel: $(SKEL)

.PHONY: clean
clean:
	rm -rf $(OBJ) $(BPF) $(OUT)

include rules.mk
