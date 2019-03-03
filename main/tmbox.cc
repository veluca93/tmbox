#include "options.h"

int main(int argc, char **argv) {
  auto options = ::options::ParseCommandLine(argc, argv);
}
