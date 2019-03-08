#pragma once

// Disables the usage of fork(). Returns -1 and sets errno on error, 0 on
// success. Will silently fail if the current OS has no support for seccomp.
// TODO: possibly revise this behavior.
int disallow_fork();
