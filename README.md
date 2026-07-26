# ebpf-lab

Lab to experiment with various eBPF programs and observability tools.

```bash
git clone --recurse-submodules https://github.com/San7o/ebpf-lab.git
```

Build an eBPF program and its loader:

- Traffic Control

```bash
make PROG_TC=1
sudo ./tc/tc
```

- XDP

```bash
make PROG_XDP=1
sudo ./xdp/xdp
```

- `sched_ext`

```bash
make PROG_SCX=1
sudo ./sched_ext/sched_ext_simple
```
- Tracepoint

```bash
make
sudo ./tp/tp
```

## My other experiments

- [Kubernetes operator managing an eBPF program to monitor file accesses](https://github.com/San7o/kivebpf)

- [Kubernetes operator using and XDP eBPF program to dump HTTP
  headers](https://github.com/dynatrace-oss/ebpf-dump) (I wrote this even if it
  is not on my github profile)

- [eBPF loader using go](https://github.com/San7o/go-ebpf)

