#pragma once
#include <optional>
#include <string.h>
#include <string>
#include <tuple>
#include <vector>

#define DEFINE_FLAG(type, name, lng, srt, desc)                                \
  struct name : public detail::Flag<type> {                                    \
    static constexpr const bool is_positional = false;                         \
    static constexpr const char *const long_name = lng;                        \
    static constexpr const char short_name = srt;                              \
    static constexpr const char *const description = desc;                     \
  };

#define DEFINE_POSITIONAL(type, cls, nm, req, desc)                            \
  struct cls : public detail::Flag<type> {                                     \
    static constexpr const bool is_positional = true;                          \
    static constexpr const bool required = req;                                \
    static constexpr const char *const name = nm;                              \
    static constexpr const char *const description = desc;                     \
  };

namespace options {
namespace detail {

template <typename T> struct Flag {
  using type = T;
  T value{};
  bool parsed = false;
  void ParseValue(const char *input);
  static constexpr const bool has_value = true;
};

template <> struct Flag<bool> {
  using type = bool;
  bool value = false;
  bool parsed = false;
  static constexpr const bool has_value = false;
};

}; // namespace detail

DEFINE_FLAG(std::string, WorkingDirectory, "directory", 'd',
            "Working directory for the execution. Defaults to the current "
            "directory.");

DEFINE_FLAG(std::string, Stdin, "stdin", 'i',
            "Absolute/relative path to stdin file.");

DEFINE_FLAG(std::string, Stdout, "stdout", 'o',
            "Absolute/relative path to stdout file.");

DEFINE_FLAG(std::string, Stderr, "stderr", 'e',
            "Absolute/relative path to stderr file.");

DEFINE_FLAG(double, TimeLimit, "time", 't', "CPU time limit, in seconds.");

DEFINE_FLAG(double, WallLimit, "wall", 'w', "Wall time limit, in seconds.");

DEFINE_FLAG(uint64_t, MemoryLimit, "memory", 'm', "Memory limit, in KiB.");

struct EnvironmentVariable {
  std::string name;
  std::optional<std::string> value;
};

DEFINE_FLAG(
    std::vector<EnvironmentVariable>, Environment, "env", 'E',
    "Environment variables, in the form NAME=VALUE. Variables with no value "
    "inherit the value from the global environment.");

DEFINE_FLAG(bool, Multithreading, "multithreading", 'p',
            "Allow more than one thread/process.");
DEFINE_FLAG(bool, Json, "json", 'j', "Print JSON output");

using Flags =
    std::tuple<WorkingDirectory, Stdin, Stdout, Stderr, TimeLimit, WallLimit,
               MemoryLimit, Environment, Multithreading, Json>;

// Positional arguments.
DEFINE_POSITIONAL(
    std::string, Executable, "executable", true,
    "Executable to run. Either absolute path, or relative to the specified "
    "working directory.");

DEFINE_POSITIONAL(std::vector<std::string>, Args, "args", false,
                  "Other arguments to the executable.");

using Positional = std::tuple<Executable, Args>;

struct Options {
  Flags flags;
  Positional positional;
  static constexpr const char *const description =
      "Runs a program under limited privileges, collecting running time and "
      "memory usage statistics.";

  template <typename Flag>
  const typename Flag::type &Get(Flag flag = Flag()) const {
    if constexpr (Flag::is_positional) {
      return std::get<Flag>(positional).value;
    } else {
      return std::get<Flag>(flags).value;
    }
  }

  template <typename Flag> const bool &Has(Flag flag = Flag()) const {
    if constexpr (Flag::is_positional) {
      return std::get<Flag>(positional).parsed;
    } else {
      return std::get<Flag>(flags).parsed;
    }
  }
};

Options ParseCommandLine(int argc, char **argv);

} // namespace options

#undef DEFINE_FLAG
#undef DEFINE_POSITIONAL
