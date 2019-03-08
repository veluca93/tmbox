#if __has_include(<linux/filter.h>)
#pragma once
#include <linux/audit.h>
#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/sched.h>
#include <linux/seccomp.h>

unsigned short disallow_fork_bpf(struct sock_filter *out, unsigned short size);

#if __i386__ || __x86_64__
unsigned short disallow_fork_bpf_i386(struct sock_filter *out,
                                      unsigned short size);
#endif

#if __x86_64__
unsigned short disallow_fork_bpf_x86_64(struct sock_filter *out,
                                        unsigned short size);
unsigned short disallow_fork_bpf_x32(struct sock_filter *out,
                                     unsigned short size);
#endif

#endif
