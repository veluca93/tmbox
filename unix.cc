#include "sandbox.h"

#include "defer.h"
#include "seccomp_filter/seccomp_filter.h"

#include <assert.h>
#include <chrono>
#include <fcntl.h>
#include <math.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <errno.h>
#include <inttypes.h>
#include <signal.h>
#include <spawn.h>

class UnixSandbox : public Sandbox {
public:
  int Priority() override {
    // This sandbox is not very secure.
    return 0;
  }
  bool CanUse() override { return true; }
  ExecutionResults Execute(const options::Options &) override;
};

namespace {

#ifdef __APPLE__
int GetProcessMemoryUsage(pid_t pid, uint64_t *memory_usage_kb) {
  int pipe_fds[2];
  if (pipe(pipe_fds) == -1)
    return errno;
  posix_spawn_file_actions_t actions;
  int ret = posix_spawn_file_actions_init(&actions);
  if (ret != 0)
    return ret;
  ret = posix_spawn_file_actions_addclose(&actions, pipe_fds[0]);
  if (ret != 0)
    return ret;
  ret = posix_spawn_file_actions_addclose(&actions, STDIN_FILENO);
  if (ret != 0)
    return ret;
  ret = posix_spawn_file_actions_adddup2(&actions, pipe_fds[1], STDOUT_FILENO);
  if (ret != 0)
    return ret;
  ret = posix_spawn_file_actions_addclose(&actions, pipe_fds[1]);
  if (ret != 0)
    return ret;

  char pid_s[20];
  sprintf(pid_s, "%d", pid);
  char *args[] = {"ps", "-o", "rss=", pid_s, nullptr};
  char *environ[] = {nullptr};

  int child_pid = 0;
  ret = posix_spawnp(&child_pid, "ps", &actions, nullptr, args, environ);
  close(pipe_fds[1]);
  if (ret != 0) {
    close(pipe_fds[0]);
    return ret;
  }
  int child_status = 0;
  if (waitpid(child_pid, &child_status, 0) == -1) {
    close(pipe_fds[0]);
    return errno;
  }
  if (child_status != 0) {
    close(pipe_fds[0]);
    *memory_usage_kb = 0;
    return 0;
  }
  char memory_usage_buf[1024] = {};
  if (read(pipe_fds[0], memory_usage_buf, 1024) == -1) {
    close(pipe_fds[0]);
    *memory_usage_kb = 0;
    return 0;
  }
  close(pipe_fds[0]);
  if (sscanf(memory_usage_buf, "%" PRIu64, memory_usage_kb) != 1) {
    *memory_usage_kb = 0;
  }
  return 0;
}
#endif

} // namespace

#define SYSCALL(call)                                                          \
  if ((call) == -1) {                                                          \
    auto saved_errno = errno;                                                  \
    results.error = true;                                                      \
    results.message = #call;                                                   \
    results.message += ": ";                                                   \
    results.message += strerror(saved_errno);                                  \
    return results;                                                            \
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

  // Working directory
  if (!OPTION(WorkingDirectory).empty()) {
    CSYSCALL(chdir(OPTION(WorkingDirectory).c_str()));
  }

  // IO redirection
  if (!OPTION(Stdin).empty()) {
    int fd;
    CSYSCALL(fd = open(OPTION(Stdin).c_str(), O_RDONLY | O_CLOEXEC));
    CSYSCALL(dup2(fd, STDIN_FILENO));
  }
  if (!OPTION(Stdout).empty()) {
    int fd;
    CSYSCALL(fd = open(OPTION(Stdout).c_str(),
                       O_WRONLY | O_CLOEXEC | O_CREAT | O_TRUNC,
                       S_IRUSR | S_IWUSR));
    CSYSCALL(dup2(fd, STDOUT_FILENO));
  }
  if (!OPTION(Stderr).empty()) {
    int fd;
    CSYSCALL(fd = open(OPTION(Stderr).c_str(),
                       O_WRONLY | O_CLOEXEC | O_CREAT | O_TRUNC,
                       S_IRUSR | S_IWUSR));
    CSYSCALL(dup2(fd, STDERR_FILENO));
  }

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

  // Setting stack size does not seem to work on MAC.
#ifndef __APPLE__
  SET_RLIM(STACK, RLIM_INFINITY);
#endif
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

#ifdef 0 // temporary disabled __APPLE__
[[noreturn]] void MemoryWatcher(int child_pid, uint64_t memory_limit_kb) {
  while (true) {
    uint64_t mem = 0;
    if (GetProcessMemoryUsage(child_pid, &mem) == 0) {
      if (memory_limit_kb != 0 && mem > memory_limit_kb) {
        kill(child_pid, SIGKILL);
      }
    }
    usleep(100);
  }
}
#endif

sig_atomic_t have_signal = 0;

void sig_hdl(int /*sig*/, siginfo_t * /*siginfo*/, void * /*context*/) {
  have_signal = 1;
}

} // namespace

ExecutionResults UnixSandbox::Execute(const options::Options &options) {
  ExecutionResults results;
  int pipefd[2];
  SYSCALL(pipe(pipefd));
  SYSCALL(fcntl(pipefd[1], F_SETFD, FD_CLOEXEC));
  int fork_result;
  SYSCALL(fork_result = fork());
  if (fork_result == 0) {
    close(pipefd[0]);
    Child(options, pipefd[1]);
  }

  int child_pid = fork_result;

  // Check that child started properly.
  SYSCALL(close(pipefd[1]));
  constexpr size_t kChildBufSize = 2048;
  char child_buf[kChildBufSize + 1] = {};
  size_t len = 0;
  while (true) {
    assert(len < kChildBufSize);
    ssize_t increment;
    SYSCALL(increment = read(pipefd[0], child_buf + len, kChildBufSize - len));
    if (increment == 0)
      break;
    len += increment;
  }
  if (len > 0) {
    waitpid(child_pid, nullptr, 0);
    results.error = true;
    results.message = "Child process: ";
    results.message += child_buf;
    return results;
  }

  // Set signal handlers for TERM and INT.
  struct sigaction act {};
  memset(&act, 0, sizeof(act));
  act.sa_sigaction = &sig_hdl;
  act.sa_flags = SA_SIGINFO;
  SYSCALL(sigaction(SIGTERM, &act, nullptr));
  SYSCALL(sigaction(SIGINT, &act, nullptr));

  // Apple only: start memory watcher.
#if 0 //FIXME: Causes tmbox to not terminate on macOS!
//#ifdef __APPLE__
  int memory_watcher_pid;
  SYSCALL(memory_watcher_pid = fork());
  if (memory_watcher_pid == 0) {
    MemoryWatcher(child_pid, OPTION(MemoryLimit));
  }
  Defer defer([&memory_watcher_pid]() {
    kill(memory_watcher_pid, SIGKILL);
    waitpid(memory_watcher_pid, nullptr, 0);
  });
#endif

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
  
#ifdef __APPLE__
  uint64_t apple_memory_usage = 0;
#endif
  while ((OPTION(WallLimit) < 1e-6 || elapsed_seconds() < OPTION(WallLimit)) &&
         !have_signal) {
    int wait_ret;
    SYSCALL(wait_ret = waitpid(child_pid, &child_status, WNOHANG));
    if (wait_ret == child_pid) {
      has_exited = true;
      break;
    }
#ifdef __APPLE__
  uint64_t mem;
  if (GetProcessMemoryUsage(child_pid, &mem) == 0) {
    if (mem > apple_memory_usage) {
      apple_memory_usage = mem;
    }
  }
#endif
    usleep(100);
  }
  if (!has_exited) {
    results.killed_by_sandbox = true;
    SYSCALL(kill(child_pid, SIGKILL));
    SYSCALL(waitpid(child_pid, &child_status, 0));
  }
  struct rusage rusage {};
  getrusage(RUSAGE_CHILDREN, &rusage);

#ifdef __APPLE__
  results.memory_usage = apple_memory_usage;
#else
  results.memory_usage = rusage.ru_maxrss;
#endif
  results.status_code = WIFEXITED(child_status) ? WEXITSTATUS(child_status) : 0;
  results.signal = WIFSIGNALED(child_status) ? WTERMSIG(child_status) : 0;
  results.wall_time = elapsed_seconds();
  results.cpu_time = rusage.ru_utime.tv_sec + rusage.ru_utime.tv_usec * 1e-6;
  results.sys_time = rusage.ru_stime.tv_sec + rusage.ru_stime.tv_usec * 1e-6;

  return results;
}

REGISTER_SANDBOX(UnixSandbox);
