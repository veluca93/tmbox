#include "sandbox.h"
#include <assert.h>
#include <unistd.h>

template <size_t N, size_t M>
ExecutionResults RunProgramWithOptions(const char *const (&args)[N],
                                       const char *program,
                                       const char *const (&program_args)[M]) {
  size_t arg = 0;
  char *args_to_pass[N + M + 3] = {};
  args_to_pass[arg++] = const_cast<char *>("");
  for (size_t i = 0; i < N; i++) {
    if (args[i][0] == 0)
      continue;
    args_to_pass[arg++] = const_cast<char *>(args[i]);
  }
  args_to_pass[arg++] = const_cast<char *>("--");
  std::string s;
  if (s[0] == '/') {
    s = program;
  } else {
    char wd[8192];
    getcwd(wd, sizeof(wd) - 1);
    s = wd;
    s += "/bin/";
    s += program;
    char *r = realpath(s.c_str(), wd);
    assert(r != nullptr);
    s = wd;
  }
  args_to_pass[arg++] = const_cast<char *>(s.c_str());
  for (size_t i = 0; i < M; i++) {
    if (program_args[i][0] == 0)
      continue;
    args_to_pass[arg++] = const_cast<char *>(program_args[i]);
  }
  auto options = options::ParseCommandLine(arg, args_to_pass);
  return SandboxRegistry::Get()->Execute(options);
}
