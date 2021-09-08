// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("tp/syscalls/sys_enter_sendto")
int handle_tp(struct trace_event_raw_sys_enter *ctx)
{
	int pid = bpf_get_current_pid_tgid() >> 32;
	int flags = ctx->args[3];
	int addr = ctx->args[4];

	bpf_printk("pid %d flags:%d, addr:%d\n", pid, flags, addr);

	return 0;
}

SEC("tp/syscalls/sys_enter_recvfrom")
int handle_tp(struct trace_event_raw_sys_enter *ctx)
{
	int pid = bpf_get_current_pid_tgid() >> 32;
	int flags = ctx->args[3];
	int addr = ctx->args[4];

	bpf_printk("PID %d flags:%d, addr:%d\n", pid, flags, addr);

	return 0;
}
