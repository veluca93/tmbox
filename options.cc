#include "options.h"
#include <assert.h>

namespace options {

namespace {
void ParseValue(const char *value, std::string *output) { *output = value; }

void ParseValue(const char *value, double *output) {
  char *end;
  *output = strtod(value, &end);
  if (*end != '\0') {
    fprintf(stderr, "Invalid double value: %s\n", value);
    exit(1);
  }
}

void ParseValue(const char *value, uint64_t *output) {
  char *end;
  *output = strtoull(value, &end, 10);
  if (*end != '\0') {
    fprintf(stderr, "Invalid positive integer value: %s\n", value);
    exit(1);
  }
}

void ParseValue(const char *value, EnvironmentVariable *output) {
  const char *first_equals = strchr(value, '=');
  if (first_equals == nullptr) {
    output->name = value;
  } else {
    output->name = std::string(value, first_equals - value);
    output->value = std::string(first_equals + 1);
  }
}

template <typename T>
void ParseValue(const char *value, std::vector<T> *output) {
  T to_add;
  ParseValue(value, &to_add);
  output->push_back(std::move(to_add));
}

constexpr bool EqualStrings(char const *a, char const *b) {
  return *a == *b && (*a == '\0' || EqualStrings(a + 1, b + 1));
}

template <typename Flag, typename OtherFlag, typename... OtherFlags>
struct CheckHasSameShortName {
  void operator()() {
    static_assert(Flag::short_name != OtherFlag::short_name,
                  "Duplicate short name!");
    if constexpr (sizeof...(OtherFlags) > 0) {
      CheckHasSameShortName<Flag, OtherFlags...>()();
    }
  }
};

template <typename Flag, typename OtherFlag, typename... OtherFlags>
struct CheckHasSameLongName {
  void operator()() {
    static_assert(!EqualStrings(Flag::long_name, OtherFlag::long_name),
                  "Duplicate long name!");
    if constexpr (sizeof...(OtherFlags) > 0) {
      CheckHasSameLongName<Flag, OtherFlags...>()();
    }
  }
};

template <typename Flag, typename... Flags> struct ValidateFlagsImpl {
  void operator()() {
    static_assert(!Flag::is_positional, "Positional argument passed as flag!");
    if constexpr (sizeof...(Flags) > 0) {
      CheckHasSameShortName<Flag, Flags...>()();
      CheckHasSameLongName<Flag, Flags...>()();
      ValidateFlagsImpl<Flags...>()();
    }
  }
};

template <typename T> struct ValidateFlags;
template <typename... Flags> struct ValidateFlags<std::tuple<Flags...>> {
  void operator()() { ValidateFlagsImpl<Flags...>()(); }
};

template <typename T> static const constexpr bool kCanRepeatValue = false;
template <typename T>
static const constexpr bool kCanRepeatValue<std::vector<T>> = true;

template <typename Flag>
static const constexpr bool kCanRepeat =
    kCanRepeatValue<typename std::remove_reference_t<Flag>::type>;

template <bool has_repeated, typename Flag, typename... Flags>
struct ValidatePositionalImpl {
  void operator()() {
    static_assert(Flag::is_positional, "Flag passed as positional argument!");
    static_assert(!kCanRepeat<Flag> || !has_repeated,
                  "Multiple repeated positional arguments!");
    if constexpr (sizeof...(Flags) > 0) {
      ValidatePositionalImpl<has_repeated | kCanRepeat<Flag>, Flags...>()();
    }
  }
};

template <typename T> struct ValidatePositional;
template <typename... Flags> struct ValidatePositional<std::tuple<Flags...>> {
  void operator()() { ValidatePositionalImpl<false, Flags...>()(); }
};

void PrintHelp(const char *program_name) {
  fprintf(stderr, "Usage: %s [<options>]", program_name);
  auto print_positional_list = [](auto pos) {
    const char *left = "[";
    const char *right = "]";
    if (pos.required) {
      left = "";
      right = "";
    }
    if (kCanRepeat<decltype(pos)>) {
      fprintf(stderr, " %s%s [ ... ] %s", left, pos.name, right);
    } else {
      fprintf(stderr, " %s%s%s", left, pos.name, right);
    }
  };

  Options dummy;

  std::apply(
      [&](auto... positionals) { (print_positional_list(positionals), ...); },
      dummy.positional);

  int max_long_flag_len = 0;
  auto upd_max = [&](int s) {
    max_long_flag_len = std::max(max_long_flag_len, s);
  };

  std::apply(
      [&](auto... flags) { (upd_max(strlen(flags.long_name) + 5), ...); },
      dummy.flags);
  std::apply(
      [&](auto... positionals) { (upd_max(strlen(positionals.name)), ...); },
      dummy.positional);

  constexpr int kMaxLen = 100;
  constexpr int kFlagIndent = 4;
  constexpr int kPostFlagSpace = 2;

  auto print_description = [&](const char *desc, int start, int width) {
    int len = strlen(desc);
    int pos = 0;
    while (pos + width < len) {
      int space_pos = pos + width;
      while (space_pos > pos && desc[space_pos] != ' ') {
        space_pos--;
      }
      bool found_space = true;
      if (space_pos == pos) {
        found_space = false;
        space_pos = pos;
      }
      fprintf(stderr, "%.*s\n%*s", space_pos - pos, desc + pos, start, "");
      pos = space_pos;
      if (found_space) {
        pos++;
      }
    }
    fprintf(stderr, "%s\n", desc + pos);
  };

  fprintf(stderr, "\n\n");
  print_description(dummy.description, 0, kMaxLen);
  fprintf(stderr, "\n");

  int description_start = max_long_flag_len + kFlagIndent + kPostFlagSpace + 1;
  int description_char_per_line =
      std::max(description_start + 10, kMaxLen) - description_start;

  auto print_flag = [&](auto flag) {
    fprintf(stderr, "%*s-%c, --%-*s%*s", kFlagIndent, "", flag.short_name,
            max_long_flag_len - 5, flag.long_name, kPostFlagSpace, "");
    print_description(flag.description, description_start,
                      description_char_per_line);
    fprintf(stderr, "\n");
  };
  auto print_positional = [&](auto positional) {
    fprintf(stderr, "%-*s %*s%*s", kFlagIndent, "", max_long_flag_len,
            positional.name, kPostFlagSpace, "");
    print_description(positional.description, description_start,
                      description_char_per_line);
    fprintf(stderr, "\n");
  };
  std::apply([&](auto... flags) { (print_flag(flags), ...); }, dummy.flags);
  std::apply([&](auto... positionals) { (print_positional(positionals), ...); },
             dummy.positional);
}

} // namespace

namespace detail {

template <typename T> void Flag<T>::ParseValue(const char *input) {
  options::ParseValue(input, &value);
}
} // namespace detail

Options ParseCommandLine(int argc, char **argv) {
  using namespace std::literals::string_literals;

  Options ret;

  ValidateFlags<decltype(ret.flags)>()();
  ValidatePositional<decltype(ret.positional)>()();

  assert(argc > 0);
  for (int arg = 1; arg < argc; arg++) {
    if (argv[arg] == "--"s) {
      break;
    }
    if (argv[arg] == "-h"s || argv[arg] == "--help"s) {
      PrintHelp(argv[0]);
      exit(0);
    }
  }

  int arg = 1;

  bool consumed = false;
  auto parse_flag = [&](auto &flag) {
    if (arg == argc) {
      return;
    }
    if (consumed) {
      return;
    }
    std::string stem;
    size_t flen = strlen(flag.long_name);
    if (flag.has_value && strlen(argv[arg]) > flen + 2 &&
        argv[arg][flen + 2] == '=') {
      stem = std::string(argv[arg], flen + 2);
    }
    if (argv[arg] != "--"s + flag.long_name &&
        argv[arg] != "-"s + flag.short_name && stem != "--"s + flag.long_name) {
      return;
    }
    if (flag.parsed && !kCanRepeat<decltype(flag)>) {
      fprintf(stderr, "Repeated flag --%s does not allow multiple values!\n",
              flag.long_name);
      exit(1);
    }
    if (flag.has_value) {
      char *val;
      if (stem.empty()) {
        arg++;
        if (arg == argc) {
          fprintf(stderr, "Missing argument for flag --%s!\n", flag.long_name);
          exit(1);
        }
        val = argv[arg];
      } else {
        val = argv[arg] + stem.size() + 1;
      }
      flag.ParseValue(val);
    }
    flag.parsed = true;
    consumed = true;
  };

  auto parse_positional = [&](auto &positional) {
    if (consumed) {
      return;
    }
    if (arg == argc)
      return;
    if (positional.parsed && !kCanRepeat<decltype(positional)>) {
      return;
    }
    positional.ParseValue(argv[arg]);
    positional.parsed = true;
    consumed = true;
  };

  for (; arg < argc; arg++) {
    if (argv[arg] == "--"s) {
      arg++;
      break;
    }
    consumed = false;
    if (argv[arg][0] != '-') {
      std::apply(
          [&](auto &... positionals) { (parse_positional(positionals), ...); },
          ret.positional);
    } else {
      std::apply([&](auto &... flags) { (parse_flag(flags), ...); }, ret.flags);
    }
    if (!consumed) {
      fprintf(stderr, "Unknown flag %s!\n", argv[arg]);
      exit(1);
    }
  }

  // After --, only positional arguments.
  for (; arg < argc; arg++) {
    consumed = false;
    std::apply(
        [&](auto &... positionals) { (parse_positional(positionals), ...); },
        ret.positional);
    if (!consumed) {
      fprintf(stderr, "Unknown flag %s!\n", argv[arg]);
      exit(1);
    }
  }

  auto check_required = [&](auto &positional) {
    if (!positional.parsed && positional.required) {
      fprintf(stderr, "Missing required flag %s!\n", positional.name);
      exit(1);
    }
  };

  std::apply([&](auto &... positionals) { (check_required(positionals), ...); },
             ret.positional);

  return ret;
}
} // namespace options
