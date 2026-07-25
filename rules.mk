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


