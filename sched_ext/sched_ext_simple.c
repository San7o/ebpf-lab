// SPDX-License-Identifier: GPL-2.0
// Author:  Giovanni Santini
// Mail:    giovanni.santini@proton.me
// Github:  @San7o

#include <bpf/libbpf.h>
#include <stdio.h>
#include <sys/resource.h>
#include <unistd.h>

#include "sched_ext.skel.h"

static volatile int should_exit;

static void sigint_handler(int arg)
{
    should_exit = true;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
        va_list args)
{
    return vfprintf(stderr, format, args);
}

int main(int argc, char **argv)
{
    struct sched_ext_simple *skel;
    struct bpf_link *link;
    __u32 opt;
    __u64 ecode;
    int err;

    libbpf_set_print(libbpf_print_fn);
    signal(SIGINT, sigint_handler);
    signal(SIGTERM, sigint_handler);

restart:
    /* Open */
    skel = SCX_OPS_OPEN(simple_ops, sched_ext_simple);
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    /* TODO: enable fifo if selected in argument */

    SCX_OPS_LOAD(skel, simple_ops, sched_ext_simple, uei);
    link = SCX_OPS_ATTACH(skel, simple_ops, scx_simple);

    while(!should_exit && !UEI_EXITED(skel, uei)) {
        __u64 stats[2];

        read_stats(skel, stats);
        printf("local=%llu gloval=%llu\n", stats[0], stats[1]);
        fflush(stdout);
        sleep(1);
    }

    bpf_link__destroy(link);
    encode = UEI_REPORT(skel, uei);
    sched_ext_simple__destroy(skel);

    if (UEI_ENCODE_RESTART(encode))
        goto restart;
    return 0;
}
