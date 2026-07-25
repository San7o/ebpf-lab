// SPDX-License-Identifier: GPL-2.0
// Author:  Giovanni Santini
// Mail:    giovanni.santini@proton.me
// Github:  @San7o

#include <bpf/libbpf.h>
#include <net/if.h>
#include <stdio.h>
#include <sys/resource.h>
#include <signal.h>
#include <stdbool.h>
#include <unistd.h>

#include "tc.skel.h"

static volatile sig_atomic_t should_close = false;

static void sig_int(int signo)
{
    should_close = true;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
        va_list args)
{
    return vfprintf(stderr, format, args);
}

int main(int argc, char **argv)
{
    struct tc_bpf *skel;
    int ifindex;
    int err;

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <interface>\n", argv[0]);
        return 1;
    }

    ifindex = if_nametoindex(argv[1]);
    if (ifindex == 0) {
        fprintf(stderr, "Invalid interface: %s\n", argv[1]);
        return 1;
    }

    DECLARE_LIBBPF_OPTS(bpf_tc_hook, tc_hook,
            .ifindex = ifindex,
            .attach_point = BPF_TC_INGRESS);
    DECLARE_LIBBPF_OPTS(bpf_tc_opts, tc_opts,
            .handle = 1, .priority = 1);

    libbpf_set_print(libbpf_print_fn);

    /* Open */
    skel = tc_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    /* Load and verify */
    err = tc_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load and verify BPF skeleton\n");
        goto cleanup;
    }

    err = bpf_tc_hook_create(&tc_hook);
    if (err && err != -EEXIST) {
        fprintf(stderr, "Failed to create TC hook: %d\n", err);
        goto cleanup;
    }

    /* Attach */
    tc_opts.prog_fd = bpf_program__fd(skel->progs.tc_ingress);
    err = bpf_tc_attach(&tc_hook, &tc_opts);
    if (err) {
        fprintf(stderr, "Failed to attach XDP program to %s\n", argv[1]);
        goto cleanup;
    }

    if (signal(SIGINT, sig_int) == SIG_ERR) {
        err = errno;
        fprintf(stderr, "Can't set signal handler: %s\n", strerror(errno));
        goto cleanup;
    }

    printf("Successfully started!\n");
    printf("Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` "
            "to see output of the BPF programs.\n");

    while (!should_close) {
        fprintf(stderr, ".");
        sleep(1);
    }

    tc_opts.flags = tc_opts.prog_fd = tc_opts.prog_id = 0;
    err = bpf_tc_detach(&tc_hook, &tc_opts);
    if (err) {
        fprintf(stderr, "Failed to detach TC: %d\n", err);
        goto cleanup;
    }

cleanup:
    bpf_tc_hook_destroy(&tc_hook);
    tc_bpf__destroy(skel);
    return -err;
}
