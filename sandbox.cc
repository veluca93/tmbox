#include "sandbox.h"
#include <assert.h>
#include <fstream>
#include <iostream>
#include <stdio.h>

Sandbox *SandboxRegistry::Get() {
  size_t best_idx = Registry().size();
  int best_priority = -1;
  for (size_t i = 0; i < Registry().size(); i++) {
    if (!Registry()[i]->CanUse())
      continue;
    int priority = Registry()[i]->Priority();
    if (priority > best_priority) {
      best_idx = i;
      best_priority = priority;
    }
  }
  if (best_priority == 0) {
    fprintf(stderr, "Warning: using unsafe sandbox!\n");
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

void PrintResults(const ExecutionResults &results, const std::string &file) {
  if (results.error) {
    fprintf(stderr, "\033[31;1mError\033[;m: %s\n", results.message.c_str());
    return;
  }
  FILE *fout = stdout;
  if (file != "") {
    fout = fopen(file.c_str(), "w");
    if (fout == nullptr) {
      fprintf(stderr, "Error opening output file!\n");
      return;
    }
  }
  if (results.killed_by_sandbox) {
    fprintf(fout, "\033[;1mKilled by sandbox\033[;m\n");
  }
  fprintf(fout, "     CPU time: %8.2f s\n", results.cpu_time);
  fprintf(fout, "  System time: %8.2f s\n", results.sys_time);
  fprintf(fout, "    Wall time: %8.2f s\n", results.wall_time);
  auto memory_usage = PrettyMemoryUsage(results.memory_usage);
  fprintf(fout, " Memory usage: %8.2f %ciB\n", memory_usage.first,
          memory_usage.second);
  if (results.status_code != 0) {
    fprintf(fout, "  Return code: %d\n", results.status_code);
  }
  if (results.signal != 0) {
    fprintf(fout, "       Signal: %s\n", strsignal(results.signal));
  }
}

void PrintJsonResults(const ExecutionResults &results,
                      const std::string &file) {
  std::ostream *fout = &std::cout;
  std::ofstream outfile;
  if (file != "") {
    outfile.open(file);
    if (outfile) {
      fout = &outfile;
    } else {
      fprintf(stderr, "Error opening output file!\n");
      return;
    }
  }
  if (results.error) {
    (*fout) << "{\"error\":true,\"message\":\"" << results.message << "\"}"
            << std::endl;
    return;
  }
  (*fout) << "{\"error\":false";
#define JSON_PRINT(key)                                                        \
  (*fout) << ",\"" << #key << "\":" << std::boolalpha << results.key;
  JSON_PRINT(cpu_time);
  JSON_PRINT(sys_time);
  JSON_PRINT(wall_time);
  JSON_PRINT(memory_usage);
  JSON_PRINT(status_code);
  JSON_PRINT(signal);
  JSON_PRINT(killed_by_sandbox);
  (*fout) << "}" << std::endl;
}
