#pragma once

struct SyscallsToBlock {
  unsigned fork : 1;
  unsigned chmod : 1;
};

#if __has_include(<linux/filter.h>)
#include <errno.h>
#include <linux/audit.h>
#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/sched.h>
#include <linux/seccomp.h>

unsigned short seccomp_filter_bpf(SyscallsToBlock to_block,
                                  struct sock_filter *out, unsigned short size);

#if __i386__ || __x86_64__
unsigned short seccomp_filter_bpf_i386(SyscallsToBlock to_block,
                                       struct sock_filter *out,
                                       unsigned short size);
#endif

#if __x86_64__
unsigned short seccomp_filter_bpf_x86_64(SyscallsToBlock to_block,
                                         struct sock_filter *out,
                                         unsigned short size);
unsigned short seccomp_filter_bpf_x32(SyscallsToBlock to_block,
                                      struct sock_filter *out,
                                      unsigned short size);
#endif

#endif
