#include "options.h"
#include "sandbox.h"

int main(int argc, char **argv) {
  auto options = ::options::ParseCommandLine(argc, argv);
  ExecutionResults results = SandboxRegistry::Get()->Execute(options);
  if (options.Get<options::Json>()) {
    PrintJsonResults(results);
  } else {
    PrintResults(results);
  }
}
