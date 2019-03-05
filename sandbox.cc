#include "sandbox.h"
#include <assert.h>
#include <iostream>

Sandbox *SandboxRegistry::Get() {
  size_t best_idx = Registry().size();
  int best_priority = -1;
  for (size_t i = 0; i < best_idx; i++) {
    if (!Registry()[i]->CanUse())
      continue;
    int priority = Registry()[i]->Priority();
    if (priority > best_priority) {
      best_idx = i;
      best_priority = priority;
    }
  }
  assert(best_idx != Registry().size());
  return Registry()[best_idx].get();
}

namespace {
std::pair<double, char> PrettyMemoryUsage(double mem) {
  constexpr char kKinds[] = "KMG";
  size_t kind = 0;
  while (mem > 1024) {
    kind++;
    mem /= 1024;
  }
  return {mem, kKinds[kind]};
}
} // namespace

void PrintResults(const ExecutionResults &results) {
  if (results.error) {
    fprintf(stderr, "\033[31;1mError\033[;m: %s\n", results.message.c_str());
    return;
  }
  if (results.killed_by_sandbox) {
    printf("\033[;1mKilled by sandbox\033[;m\n");
  }
  printf("CPU time: %f\n", results.cpu_time);
  printf("System time: %f\n", results.sys_time);
  printf("Wall time: %f\n", results.wall_time);
  auto memory_usage = PrettyMemoryUsage(results.memory_usage);
  printf("Memory usage: %5.3f%ciB\n", memory_usage.first, memory_usage.second);
  if (results.status_code != 0) {
    printf("Return code: %d\n", results.status_code);
  }
  if (results.signal != 0) {
    printf("Signal: %s\n", strsignal(results.signal));
  }
}

void PrintJsonResults(const ExecutionResults &results) {
  if (results.error) {
    std::cout << "{\"error\":true,\"message\":\"" << results.message << "\"}"
              << std::endl;
    return;
  }
  std::cout << "{\"error\":false";
#define JSON_PRINT(key)                                                        \
  std::cout << ",\"" << #key << "\":" << std::boolalpha << results.key;
  JSON_PRINT(cpu_time);
  JSON_PRINT(sys_time);
  JSON_PRINT(wall_time);
  JSON_PRINT(memory_usage);
  JSON_PRINT(status_code);
  JSON_PRINT(signal);
  JSON_PRINT(killed_by_sandbox);
  std::cout << "}" << std::endl;
}
