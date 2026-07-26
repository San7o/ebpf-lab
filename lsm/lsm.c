// SPDX-License-Identifier: GPL-2.0
// Author:  Giovanni Santini
// Mail:    giovanni.santini@proton.me
// Github:  @San7o

#include <bpf/libbpf.h>
#include <stdio.h>
#include <sys/resource.h>
#include <unistd.h>

#include "lsm.skel.h"

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
        va_list args)
{
    return vfprintf(stderr, format, args);
}

int main(int argc, char **argv)
{
    struct lsm_bpf *skel;
    int err;

    libbpf_set_print(libbpf_print_fn);

    /* Open */
    skel = lsm_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    /* Load and verify */
    err = lsm_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load and verify BPF skeleton\n");
        goto cleanup;
    }

    /* Attach */
    err = lsm_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }

    printf("Succesfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` "
            "to see oulsmut of the BPF programs.\n");

    for (;;) {
        fprintf(stderr, ".");
        sleep(1);
    }

cleanup:
    lsm_bpf__destroy(skel);
    return -err;
}
