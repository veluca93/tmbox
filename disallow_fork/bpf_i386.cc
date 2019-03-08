#if __has_include(<linux/filter.h>)
#include "disallow_fork/bpf.h"
#include <assert.h>
#include <stddef.h>
#define ARCH AUDIT_ARCH_I386

#if __i386__
#include <asm/unistd.h>
unsigned short disallow_fork_bpf_i386(struct sock_filter *out,
                                      unsigned short size) {
#include "bpf-inl.h"
}
#endif

#if __x86_64__
#undef __x86_64__
#define __i386__
#include <asm/unistd.h>
unsigned short disallow_fork_bpf_i386(struct sock_filter *out,
                                      unsigned short size) {
#include "bpf-inl.h"
}
#endif

#endif
