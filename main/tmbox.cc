#include "options.h"
#include "sandbox.h"

int main(int argc, char **argv) {
  auto options = ::options::ParseCommandLine(argc, argv);
  ExecutionResults results; // TODO: call the sandbox.
  if (options.Get<options::Json>()) {
    PrintJsonResults(results);
  } else {
    PrintResults(results);
  }
}
