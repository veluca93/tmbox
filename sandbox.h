#pragma once
#include "options.h"
#include <memory>

struct ExecutionResults {
  double cpu_time = 0;
  double sys_time = 0;
  double wall_time = 0;
  uint64_t memory_usage = 0;

  int32_t status_code = 0;
  int32_t signal = 0;
  bool killed_by_sandbox = false;

  bool error = false;
  std::string message;
};

class Sandbox {
public:
  virtual ExecutionResults Execute(const options::Options &options) = 0;
  virtual bool CanUse() = 0;
  virtual int Priority() = 0;
  virtual ~Sandbox() {}
};

class SandboxRegistry {
public:
  static void Register(std::unique_ptr<Sandbox> sandbox) {
    Registry().push_back(std::move(sandbox));
  }
  static Sandbox *Get();

private:
  using reg_t = std::vector<std::unique_ptr<Sandbox>>;
  static reg_t &Registry() {
    static reg_t registry;
    return registry;
  }
};

void PrintResults(const ExecutionResults &results);
void PrintJsonResults(const ExecutionResults &results);

namespace detail {
template <typename Sandbox> class Register {
public:
  Register() { SandboxRegistry::Register(std::make_unique<Sandbox>()); }
};
} // namespace detail

#define REGISTER_SANDBOX(Sandbox)                                              \
  namespace {                                                                  \
  detail::Register<Sandbox> register_##Sandbox;                                \
  }
