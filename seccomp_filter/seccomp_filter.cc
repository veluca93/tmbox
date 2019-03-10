#include "seccomp_filter.h"

#if !__has_include(<linux/seccomp.h>)
#warn "No support for disallowing fork."
int seccomp_filter() { return 0; }
#else

#include <errno.h>
#include <stddef.h>

#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>

#include "seccomp_filter/bpf.h"

int seccomp_filter(SyscallsToBlock to_block) {
  // No syscall should be blocked. Do nothing.
  if (to_block.chmod == false && to_block.fork == false)
    return 0;
  constexpr size_t kMaxFilterSize = 4096;
  struct sock_filter filter[kMaxFilterSize];
  unsigned short filter_size =
      seccomp_filter_bpf(to_block, filter, kMaxFilterSize);
  struct sock_fprog prog {
    filter_size, filter
  };
  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1) {
    return -1;
  }
  return prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog);
}
#endif
