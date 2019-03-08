// On some architectures, the flags of clone don't appear as the first argument.
#ifndef CLONE_FLAG_INDEX
#define CLONE_FLAG_INDEX 0
#endif
struct sock_filter filter[] = {
    // Load arch identifier of the syscall.
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
    // If this is the wrong arch, skip this filter.
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, ARCH, 0, 255 /*will be replaced*/),
    // Syscall number
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
    // Block vfork.
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_vfork, 4, 0),
    // Allow anything that is not clone.
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_clone, 0, 2),
    // Load flags for the clone syscall.
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
             offsetof(struct seccomp_data, args[CLONE_FLAG_INDEX])),
    // Allow creation of threads (CLONE_THREAD is set).
    BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, CLONE_THREAD, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    // Otherwise, kill the program.
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL),
};

unsigned num_instr = sizeof filter / sizeof *filter;

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
