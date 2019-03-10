#pragma once
#include "seccomp_filter/bpf.h"

// Disables the usage of the specified calls. Returns -1 and sets errno on
// error, 0 on success. Will silently fail if the current OS has no support for
// seccomp.
// TODO: possibly revise this behavior.
int seccomp_filter(SyscallsToBlock to_block);
