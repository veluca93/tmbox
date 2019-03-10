// On some architectures, the flags of clone don't appear as the first argument.
#ifndef CLONE_FLAG_INDEX
#define CLONE_FLAG_INDEX 0
#endif
struct sock_filter filter[4096];
unsigned num_instr = 0;
// Prelude
// Load arch identifier of the syscall.
filter[num_instr++] =
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch));
// If this is the wrong arch, skip this filter.
filter[num_instr++] =
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, ARCH, 0, 255 /*will be replaced*/);

if (to_block.fork) {
  // Syscall number
  filter[num_instr++] =
      BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr));
  // Block vfork.
  filter[num_instr++] = BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_vfork, 4, 0);
  // If this is clone...
  filter[num_instr++] = BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_clone, 0, 4);
  // Load flags for the clone syscall.
  filter[num_instr++] =
      BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
               offsetof(struct seccomp_data, args[CLONE_FLAG_INDEX]));
  // Allow creation of threads (CLONE_THREAD is set).
  filter[num_instr++] =
      BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, CLONE_THREAD, 0, 1);
  filter[num_instr++] = BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
  // Otherwise, kill the program.
  filter[num_instr++] = BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL);
}

if (to_block.chmod) {
  // Syscall number
  filter[num_instr++] =
      BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr));
  // Block chmod.
  filter[num_instr++] = BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_chmod, 2, 0);
  // Block fchmod.
  filter[num_instr++] = BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_fchmod, 1, 0);
  // Block fchmodat.
  filter[num_instr++] =
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_fchmodat, 0, 1);
  filter[num_instr++] = BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM);
}
// Allow anything else.
filter[num_instr++] = BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);

assert(num_instr > 2);
assert(num_instr < 256);

// Write down the correct number of instructions to skip to skip this filter.
filter[1].jf = (unsigned char)(num_instr - 2);

assert(num_instr < size);

// Write the filter in the output.
for (unsigned i = 0; i < num_instr; i++) {
  out[i] = filter[i];
}
return num_instr;
