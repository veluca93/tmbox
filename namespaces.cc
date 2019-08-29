#if __linux__
#include "sandbox.h"

#include "defer.h"
#include "seccomp_filter/seccomp_filter.h"

#include <assert.h>
#include <chrono>
#include <fcntl.h>
#include <math.h>
#include <sched.h>
#include <stddef.h>
#include <sys/mount.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/wait.h>
#include <unistd.h>

class NamespaceSandbox : public Sandbox {
public:
  int Priority() override {
    // This sandbox is OK to use.
    return 1;
  }
  bool CanUse() override;
  ExecutionResults Execute(const options::Options &) override;
};

bool NamespaceSandbox::CanUse() {
  int pid = fork();
  assert(pid != -1);
  if (pid == 0) {
    _exit(unshare(CLONE_NEWUSER) == 0);
  }
  int child_ret;
  pid_t ret = waitpid(pid, &child_ret, 0);
  assert(ret == pid);
  return child_ret;
}

#define CSYSCALL(call)                                                         \
  if ((call) == -1) {                                                          \
    auto saved_errno = errno;                                                  \
    const char *prefix = #call ": ";                                           \
    int plen = strlen(prefix);                                                 \
    write(fd, prefix, plen);                                                   \
    const char *err = strerror(saved_errno);                                   \
    int elen = strlen(err);                                                    \
    write(fd, err, elen);                                                      \
    _Exit(1);                                                                  \
  }

#define OPTION(opt) options.Get<options::opt>()

namespace {
[[noreturn]] void Child(const options::Options &options, int fd) {

  // Change process group.
  CSYSCALL(setsid());

  // Argument list
  auto &exe = OPTION(Executable);
  auto &other_args = OPTION(Args);
  std::vector<char *> args(2 + other_args.size());
  args[0] = const_cast<char *>(exe.c_str());
  args.back() = nullptr;
  for (size_t i = 0; i < other_args.size(); i++) {
    args[i + 1] = const_cast<char *>(other_args[i].c_str());
  }

  // Resource limits
#define SET_RLIM(res, value)                                                   \
  {                                                                            \
    rlim_t limit = value;                                                      \
    if (limit) {                                                               \
      struct rlimit rlim {};                                                   \
      rlim.rlim_cur = limit;                                                   \
      rlim.rlim_max = limit;                                                   \
      CSYSCALL(setrlimit(RLIMIT_##res, &rlim));                                \
    }                                                                          \
  }
  SET_RLIM(AS, OPTION(MemoryLimit) * 1024);
  SET_RLIM(CPU, ceil(OPTION(TimeLimit)));
  SET_RLIM(FSIZE, ceil(OPTION(FsizeLimit)) * 1024);
  SET_RLIM(CORE, 0);

  SET_RLIM(STACK, RLIM_INFINITY);
#undef SET_RLIM

  // Environment variables
  auto &env = OPTION(Environment);
  std::vector<std::string> env_mem;
  std::vector<char *> envp;

  for (size_t i = 0; i < env.size(); i++) {
    if (env[i].value.has_value()) {
      env_mem.push_back(env[i].name + "=" + *env[i].value);
    } else {
      char *current = getenv(env[i].name.c_str());
      if (current == nullptr)
        continue;
      env_mem.push_back(env[i].name + "=" + current);
    }
    envp.push_back(const_cast<char *>(env_mem.back().c_str()));
  }
  envp.push_back(nullptr);

  // Block disallowed syscalls.
  SyscallsToBlock to_block;
  to_block.chmod = !OPTION(AllowChmod);
  to_block.fork = !OPTION(Multiprocess);
  CSYSCALL(seccomp_filter(to_block));

  CSYSCALL(execve(exe.c_str(), args.data(), envp.data()));

  // execve either fails or does not return.
  fprintf(stderr, "The impossible happened!\n");
  _Exit(123);
}

sig_atomic_t have_signal = 0;

void sig_hdl(int /*sig*/, siginfo_t * /*siginfo*/, void * /*context*/) {
  have_signal = 1;
}

#define KSYSCALL_EV(call, error_value)                                         \
  if ((call) == error_value && errno != EEXIST) {                              \
    auto saved_errno = errno;                                                  \
    const char *prefix = #call ": ";                                           \
    int plen = strlen(prefix);                                                 \
    const char *err = strerror(saved_errno);                                   \
    int elen = strlen(err);                                                    \
    unsigned error_len = plen + elen;                                          \
    write(fd, &error_len, sizeof error_len);                                   \
    write(fd, prefix, plen);                                                   \
    write(fd, err, elen);                                                      \
    _Exit(1);                                                                  \
  }

#define KSYSCALL(call) KSYSCALL_EV(call, -1)

[[noreturn]] void SandboxKeeper(const options::Options &options, int fd,
                                int uid, int gid, const char *temp_dir) {
  ExecutionResults results;
  int pipefd[2];
  KSYSCALL(pipe(pipefd));
  KSYSCALL(fcntl(pipefd[1], F_SETFD, FD_CLOEXEC));

  // Setup uid and gid map.
#define WRITE_TO_FILE(file, str)                                               \
  {                                                                            \
    std::string s = str;                                                       \
    int f;                                                                     \
    KSYSCALL(f = open(file, O_RDWR));                                          \
    KSYSCALL(write(f, s.c_str(), s.size()));                                   \
    KSYSCALL(close(f));                                                        \
  }

  WRITE_TO_FILE("/proc/self/uid_map",
                std::to_string(uid) + " " + std::to_string(uid) + " 1");
  WRITE_TO_FILE("/proc/self/setgroups", "deny");
  WRITE_TO_FILE("/proc/self/gid_map",
                std::to_string(gid) + " " + std::to_string(gid) + " 1");

  // Working directory
  if (!OPTION(WorkingDirectory).empty()) {
    KSYSCALL(chdir(OPTION(WorkingDirectory).c_str()));
  }

  // IO redirection
  if (!OPTION(Stdin).empty()) {
    int fd;
    KSYSCALL(fd = open(OPTION(Stdin).c_str(), O_RDONLY | O_CLOEXEC));
    KSYSCALL(dup2(fd, STDIN_FILENO));
  }
  if (!OPTION(Stdout).empty()) {
    int fd;
    KSYSCALL(fd = open(OPTION(Stdout).c_str(),
                       O_WRONLY | O_CLOEXEC | O_CREAT | O_TRUNC,
                       S_IRUSR | S_IWUSR));
    KSYSCALL(dup2(fd, STDOUT_FILENO));
  }
  if (!OPTION(Stderr).empty()) {
    int fd;
    KSYSCALL(fd = open(OPTION(Stderr).c_str(),
                       O_WRONLY | O_CLOEXEC | O_CREAT | O_TRUNC,
                       S_IRUSR | S_IWUSR));
    KSYSCALL(dup2(fd, STDERR_FILENO));
  }

  KSYSCALL(mount("", temp_dir, "tmpfs", MS_NOEXEC, ""));

#define MAKEDIRS(d)                                                            \
  {                                                                            \
    std::string dir = d;                                                       \
    for (size_t i = 1; i < dir.size() + 1; i++) {                              \
      if (i == dir.size() || dir[i] == '/') {                                  \
        std::string sub = dir.substr(0, i);                                    \
        KSYSCALL(mkdir(sub.c_str(), S_IRWXU));                                 \
      }                                                                        \
    }                                                                          \
  }

  const auto &readable_dirs = OPTION(ReadableDir);

  char wd_buf[8192];
  KSYSCALL_EV(getcwd(wd_buf, sizeof(wd_buf) - 1), nullptr);

  for (size_t i = 0; i < readable_dirs.size(); i++) {
    auto tgt = temp_dir + readable_dirs[i];
    MAKEDIRS(tgt);
    KSYSCALL(
        mount(readable_dirs[i].c_str(), tgt.c_str(), "", MS_BIND | MS_REC, ""));
    KSYSCALL(mount("", tgt.c_str(), "", MS_REMOUNT | MS_BIND | MS_RDONLY, ""));
  }
  if (OPTION(MountTmpfs)) {
    std::string dev = std::string(temp_dir) + "/dev";
    MAKEDIRS(dev);
    KSYSCALL(mount("tmpfs", dev.c_str(), "tmpfs", 0, ""));
    std::string dev_null = std::string(temp_dir) + "/dev/null";
    KSYSCALL(mknod(dev_null.c_str(),
                   S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH,
                   makedev(1, 3)));
    std::string tmp = std::string(temp_dir) + "/tmp";
    MAKEDIRS(tmp);
    KSYSCALL(mount("tmpfs", tmp.c_str(), "tmpfs", 0, "size=256M"));
  }

  std::string new_wd = std::string(temp_dir) + wd_buf;
  MAKEDIRS(new_wd)
  KSYSCALL(mount(wd_buf, new_wd.c_str(), "", MS_BIND | MS_REC, ""));

  // Done setting up evaluation chroot, remount tmpdir readonly.
  KSYSCALL(mount("", temp_dir, "", MS_REMOUNT | MS_RDONLY, ""));

  // Chroot in the new hierarchy and go to the correct working directory.
  KSYSCALL(chroot(temp_dir));
  KSYSCALL(chdir(wd_buf));

  int fork_result;
  KSYSCALL(fork_result = fork());
  if (fork_result == 0) {
    close(pipefd[0]);
    Child(options, pipefd[1]);
  }

  int child_pid = fork_result;

  // Check that child started properly.
  KSYSCALL(close(pipefd[1]));
  constexpr size_t kChildBufSize = 2048;
  char child_buf[kChildBufSize + 1] = {};
  size_t len = 0;
  while (true) {
    assert(len < kChildBufSize);
    ssize_t increment;
    KSYSCALL(increment = read(pipefd[0], child_buf + len, kChildBufSize - len));
    if (increment == 0)
      break;
    len += increment;
  }
  if (len > 0) {
    waitpid(child_pid, nullptr, 0);
    results.error = true;
    results.message = "Child process: ";
    results.message += child_buf;
    unsigned error_len = results.message.size();
    write(fd, &error_len, sizeof error_len);
    write(fd, results.message.c_str(), results.message.size());
    _Exit(1);
  }

  // Set signal handlers for TERM and INT.
  struct sigaction act {};
  memset(&act, 0, sizeof(act));
  act.sa_sigaction = &sig_hdl;
  act.sa_flags = SA_SIGINFO;
  KSYSCALL(sigaction(SIGTERM, &act, nullptr));
  KSYSCALL(sigaction(SIGINT, &act, nullptr));

  // Child process started correctly: wait loop.
  auto program_start = std::chrono::high_resolution_clock::now();
  auto elapsed_seconds = [&program_start]() {
    return std::chrono::duration_cast<
               std::chrono::duration<double, std::ratio<1>>>(
               std::chrono::high_resolution_clock::now() - program_start)
        .count();
  };

  bool has_exited = false;
  int child_status = 0;
  while ((OPTION(WallLimit) < 1e-6 || elapsed_seconds() < OPTION(WallLimit)) &&
         !have_signal) {
    int wait_ret;
    KSYSCALL(wait_ret = waitpid(child_pid, &child_status, WNOHANG));
    if (wait_ret == child_pid) {
      has_exited = true;
      break;
    }
    usleep(100);
  }
  if (!has_exited) {
    results.killed_by_sandbox = true;
    KSYSCALL(kill(child_pid, SIGKILL));
    KSYSCALL(waitpid(child_pid, &child_status, 0));
  }
  struct rusage rusage {};
  getrusage(RUSAGE_CHILDREN, &rusage);
  results.memory_usage = rusage.ru_maxrss;

  results.status_code = WIFEXITED(child_status) ? WEXITSTATUS(child_status) : 0;
  results.signal = WIFSIGNALED(child_status) ? WTERMSIG(child_status) : 0;
  results.wall_time = elapsed_seconds();
  results.cpu_time = rusage.ru_utime.tv_sec + rusage.ru_utime.tv_usec * 1e-6;
  results.sys_time = rusage.ru_stime.tv_sec + rusage.ru_stime.tv_usec * 1e-6;

  unsigned error_len = 0;
  write(fd, &error_len, sizeof error_len);
  write(fd, &results, offsetof(ExecutionResults, error));
  _Exit(0);
}

} // namespace

#define SYSCALL_EV(call, error_value)                                          \
  if ((call) == error_value && errno != EAGAIN) {                              \
    auto saved_errno = errno;                                                  \
    results.error = true;                                                      \
    results.message = #call;                                                   \
    results.message += ": ";                                                   \
    results.message += strerror(saved_errno);                                  \
    return results;                                                            \
  }

#define SYSCALL(call) SYSCALL_EV(call, -1)

#define WAITKEEPER()                                                           \
  {                                                                            \
    int child_ret;                                                             \
    int wait_ret = waitpid(child_pid, &child_ret, 0);                          \
    assert(wait_ret == child_pid);                                             \
    if (WIFSIGNALED(child_ret)) {                                              \
      results.error = true;                                                    \
      results.message = "Keeper died with signal ";                            \
      results.message += strsignal(WTERMSIG(child_ret));                       \
      return results;                                                          \
    }                                                                          \
    if (WIFEXITED(child_ret) && WEXITSTATUS(child_ret) != 0) {                 \
      results.error = true;                                                    \
      results.message = "Keeper died with return code ";                       \
      results.message += std::to_string(WEXITSTATUS(child_ret));               \
      return results;                                                          \
    }                                                                          \
  }

ExecutionResults NamespaceSandbox::Execute(const options::Options &options) {
  ExecutionResults results;

  char tmpdir[] = "/tmp/tmboxXXXXXX";
  SYSCALL_EV(mkdtemp(tmpdir), nullptr);
  Defer defer([&]() {
    int ret = rmdir(tmpdir);
    if (ret == -1) {
      if (!results.error) {
        fprintf(stderr, "Error removing temporary directory: %s\n",
                strerror(errno));
      }
    }
  });

  int uid = getuid();
  int gid = getgid();

  int pipefd[2];
  SYSCALL(pipe2(pipefd, O_NONBLOCK));
  int fork_result;
  SYSCALL(fork_result =
              syscall(SYS_clone,
                      CLONE_NEWIPC | CLONE_NEWNET | CLONE_NEWNS | CLONE_NEWPID |
                          CLONE_NEWUSER | CLONE_NEWUTS | SIGCHLD,
                      nullptr));
  if (fork_result == 0) {
    close(pipefd[0]);
    SandboxKeeper(options, pipefd[1], uid, gid, tmpdir);
  }

  int child_pid = fork_result;

  // Set signal handlers for TERM and INT.
  struct sigaction act {};
  memset(&act, 0, sizeof(act));
  act.sa_sigaction = &sig_hdl;
  act.sa_flags = SA_SIGINFO;
  SYSCALL(sigaction(SIGTERM, &act, nullptr));
  SYSCALL(sigaction(SIGINT, &act, nullptr));

  // Check for errors from the keeper.
  SYSCALL(close(pipefd[1]));
  unsigned error_len = 0;
  bool signaled_keeper = false;
  while (true) {
    if (have_signal && !signaled_keeper) {
      kill(child_pid, SIGINT);
      signaled_keeper = true;
    }
    ssize_t ret;
    SYSCALL(ret = read(pipefd[0], &error_len, sizeof error_len));
    if (ret == -1) {
      usleep(100);
      continue;
    }
    if (ret == 0) {
      WAITKEEPER();
      results.error = true;
      results.message = "Keeper died without sending results!";
      return results;
    }
    break;
  }

  // Read either message or error from keeper.
  std::vector<char> error_buf;
  char *target;
  unsigned len;
  if (error_len > 0) {
    error_buf.resize(error_len);
    target = error_buf.data();
    len = error_len;
  } else {
    target = (char *)&results;
    len = offsetof(ExecutionResults, error);
  }
  unsigned num_read = 0;
  while (num_read < len) {
    ssize_t ret;
    SYSCALL(ret = read(pipefd[0], target + num_read, len - num_read));
    if (ret == -1) {
      usleep(100);
      continue;
    }
    num_read += ret;
    if (ret == 0 && num_read < len) {
      WAITKEEPER();
      results.error = true;
      results.message = "Keeper died during response!";
      return results;
    }
  }

  // Return error from keeper, if any.
  if (error_len > 0) {
    waitpid(child_pid, nullptr, 0);
    results.error = true;
    results.message = "Keeper: ";
    results.message += std::string(error_buf.data(), error_buf.size());
    return results;
  }
  WAITKEEPER();

  return results;
}

REGISTER_SANDBOX(NamespaceSandbox);
#endif
