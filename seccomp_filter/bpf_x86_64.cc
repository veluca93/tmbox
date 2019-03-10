#if __has_include(<linux/filter.h>)
#include "seccomp_filter/bpf.h"
#include <assert.h>
#include <stddef.h>
#define ARCH AUDIT_ARCH_X86_64

#if __x86_64__
#ifdef __ILP32__
#undef __ILP32__
#endif
#include <asm/unistd.h>
unsigned short seccomp_filter_bpf_x86_64(SyscallsToBlock to_block,
                                         struct sock_filter *out,
                                         unsigned short size) {
#include "bpf-inl.h"
}
#endif

#endif
