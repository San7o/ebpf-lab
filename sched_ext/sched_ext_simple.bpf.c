// SPDX-License-Identifier: GPL-2.0
// Author:  Giovanni Santini
// Mail:    giovanni.santini@proton.me
// Github:  @San7o

// Source: https://github.com/sched-ext/scx-c-examples/blob/main/scheds/c/scx_simple.bpf.c

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#include "scx/enums.autogen.bpf.h"
#include "scx/common.bpf.h"
#include "scx/compat.bpf.h"

char LICENSE[] SEC("license") = "GPL";

enum uei_sizes {
	UEI_REASON_LEN		= 128,
	UEI_MSG_LEN		= 1024,
	UEI_DUMP_DFL_LEN	= 32768,
};

struct user_exit_info {
	int		kind;
	s64		exit_code;
	char		reason[UEI_REASON_LEN];
	char		msg[UEI_MSG_LEN];
};

const volatile bool fifo_sched;

static u64 vtime_now;
UEI_DEFINE(uei);

#define SHARED_DSQ 0

s32 scx_bpf_select_cpu_dfl(struct task_struct *p, s32 prev_cpu, u64 wake_flags, bool *is_idle) __ksym;

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u64));
    __uint(max_entries, 2);
} stats SEC(".maps");

static void stat_inc(u32 idx)
{
    u64 *cnt_p = bpf_map_lookup_elem(&stats, &idx);
    if (cnt_p)
        (*cnt_p)++;
}

/* Struct ops */

s32 BPF_STRUCT_OPS(simple_select_cpu, struct task_struct *p,
                   s32 prev_cpu, u64 wake_flags)
{
    bool is_idle = false;
    s32 cpu;

    cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);
    if (is_idle) {
        stat_inc(0);   /* local queing */
        scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, 0);
    }

    return cpu;
}

void BPF_STRUCT_OPS(simple_enqueue, struct task_struct *p, u64 enq_flags)
{
    stat_inc(1);   /* global queing */

    if (fifo_sched) {
        scx_bpf_dsq_insert(p, SHARED_DSQ, SCX_SLICE_DFL, enq_flags);
    } else {
        u64 vtime = p->scx.dsq_vtime;

        /* Limit the about of budget that an idling task can accumulate to one
         * slice. */
        if (time_before(vtime, vtime_now - SCX_SLICE_DFL))
            vtime = vtime_now - SCX_SLICE_DFL;

        scx_bpf_dsq_insert_vtime(p, SHARED_DSQ, SCX_SLICE_DFL,
                                 vtime, enq_flags);
    }
}

void BPF_STRUCT_OPS(simple_dispatch, s32 cpu, struct task_struct *prev)
{
    scx_bpf_sdq_move_to_local(SHARED_DSQ);
}

void BPF_STRUCT_OPS(simple_dispatch, s32 cpu, struct task_struct *prev)
{
    scx_bpf_dsq_move_to_local(SHARED_DSQ);
}

void BPF_STRUCT_OPS(simple_running, struct task_struct *p)
{
    if (fifo_sched)
        return;

    /* Global vtime always progresses forward as tasks start executing. The test
     * and update can be performed concurrently from multiple CPUs and thus
     * racy. Any error should be contained and temporary. Let's just live with
     * it. */
    if (time_before(vtime_now, p->scx.dsq_vtime))
        vtime_now = p->scx.dsq_vtime;
}

void BPF_STRUCT_OPS(simple_stopping, struct task_struct *p, bool runnable)
{
    if (fifo_sched)
        return;

    /* Scale the execution time by the inverse of the weight and charge */
    p->scx.dsq_vtime += (SCX_SLICE_DFL - p->scx.slice) * 100 / p->scx.weight;
}

void BPF_STRUCT_OPS(simple_enable, struct task_struct *p)
{
    p->scx.dsq_vtime = vtime_now;
}

s32 BPF_STRUCT_OPS_SLEEPABLE(simple_init)
{
    return scx_bpf_create_dsq(SHARED_DSQ, -1);
}

void BPF_STRUCT_OPS(simple_exit, struct scx_exit_info *ei)
{
    UEI_RECORD(uei, ei);
}

SCX_OPS_DEFINE(simple_ops,
        .select_cpu = (void*)simple_select_cpu,
        .enqueue    = (void*)simple_enqueue,
        .dispatch   = (void*)simple_dispatch,
        .running    = (void*)simple_running,
        .stopping   = (void*)simple_stopping,
        .enable     = (void*)simple_enable,
        .init       = (void*)simple_init,
        .exit       = (void*)simple_exit,
        .anme       = "simple");
