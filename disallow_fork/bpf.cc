#if __has_include(<linux/filter.h>)
#include "disallow_fork/bpf.h"
#include <assert.h>

namespace {
// Kill a program that does a syscall from a not-recognized architecture.
constexpr struct sock_filter kEnd = BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL);
} // namespace

#if __i386__
unsigned short disallow_fork_bpf(struct sock_filter *out, unsigned short size) {
  unsigned short cur = 0;
  cur += disallow_fork_bpf_i386(out + cur, size - cur);
  assert(cur < size);
  out[cur++] = kEnd;
  return cur;
}
#elif __x86_64__
unsigned short disallow_fork_bpf(struct sock_filter *out, unsigned short size) {
  unsigned short cur = 0;
  cur += disallow_fork_bpf_x86_64(out + cur, size - cur);
  cur += disallow_fork_bpf_i386(out + cur, size - cur);
  cur += disallow_fork_bpf_x32(out + cur, size - cur);
  assert(cur < size);
  out[cur++] = kEnd;
  return cur;
}
#else
#error "Non-x86 architectures are not supported yet!"
#endif
#endif
