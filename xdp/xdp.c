// SPDX-License-Identifier: GPL-2.0
// Author:  Giovanni Santini
// Mail:    giovanni.santini@proton.me
// Github:  @San7o

#include <bpf/libbpf.h>
#include <net/if.h>
#include <stdio.h>
#include <sys/resource.h>
#include <unistd.h>

#include "xdp.skel.h"

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
        va_list args)
{
    return vfprintf(stderr, format, args);
}

int main(int argc, char **argv)
{
    struct bpf_link *link = NULL;
    struct xdp_bpf *skel;
    int ifindex;
    int err;

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <interface>\n", argv[0]);
        return 1;
    }

    ifindex = if_nametoindex(argv[1]);
    if (ifindex == 0) {
        fprintf(stderr, "Invalid interfce name: %s\n", argv[1]);
        return 1;
    }

    libbpf_set_print(libbpf_print_fn);

    /* Open */
    skel = xdp_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    /* Load and verify */
    err = xdp_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load and verify BPF skeleton\n");
        goto cleanup;
    }

    /* Attach */
    link = bpf_program__attach_xdp(skel->progs.handle_xdp, ifindex);
    if (!link) {
        err = -1;
        fprintf(stderr, "Failed to attach XDP program to %s\n", argv[1]);
        goto cleanup;
    }

    printf("Succesfully attached to interface %s (ifindex %d)!\n",
            argv[1], ifindex);
    printf("Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` "
            "to see ouxdput of the BPF programs.\n");

    for (;;) {
        fprintf(stderr, ".");
        sleep(1);
    }

cleanup:
    bpf_link__destroy(link);
    xdp_bpf__destroy(skel);
    return -err;
}
