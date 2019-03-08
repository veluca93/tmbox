#include "options.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

namespace options {
namespace {

using testing::ElementsAre;
using testing::Eq;
using testing::ExitedWithCode;

const char *kProgramName = "test_program";

template <size_t N> Options ParseGivenArgs(const char *const (&args)[N]) {
  char *args_to_pass[N + 2] = {};
  args_to_pass[0] = const_cast<char *>(kProgramName);
  for (size_t i = 0; i < N; i++) {
    args_to_pass[i + 1] = const_cast<char *>(args[i]);
  }
  return ParseCommandLine(N + 1, args_to_pass);
}

TEST(OptionsTest, HelpContainsProgramName) {
  EXPECT_EXIT(ParseGivenArgs({"--help"}), ExitedWithCode(0), kProgramName);
  EXPECT_EXIT(ParseGivenArgs({"-h"}), ExitedWithCode(0), kProgramName);
}

TEST(OptionsTest, RepeatedFlagError) {
  EXPECT_DEATH(ParseGivenArgs({"-e", "a", "-e", "b"}), "Repeated flag");
}

TEST(OptionsTest, UnknownFlagError) {
  EXPECT_DEATH(ParseGivenArgs({"--very_misterous_flag"}), "Unknown flag");
}

TEST(OptionsTest, MissingRequiredPositional) {
  EXPECT_DEATH(ParseGivenArgs({"-e", "a"}), "Missing required flag");
}

TEST(OptionsTest, MissingFlagArgument) {
  EXPECT_DEATH(ParseGivenArgs({"-e"}), "Missing argument for flag");
}

TEST(OptionsTest, ParsesPositional) {
  auto options = ParseGivenArgs({"foo"});
  EXPECT_THAT(options.Get<Executable>(), Eq("foo"));
}

TEST(OptionsTest, ParsesPositionalAfterDoubleDash) {
  auto options = ParseGivenArgs({"--", "--foo"});
  EXPECT_THAT(options.Get<Executable>(), Eq("--foo"));
}

TEST(OptionsTest, ParsesShortFlag) {
  auto options = ParseGivenArgs({"-e", "foo", "exe"});
  EXPECT_THAT(options.Get<Stderr>(), Eq("foo"));
  EXPECT_THAT(options.Get<Executable>(), Eq("exe"));
}

TEST(OptionsTest, ParsesLongFlag) {
  auto options = ParseGivenArgs({"--stderr", "foo", "exe"});
  EXPECT_THAT(options.Get<Stderr>(), Eq("foo"));
  EXPECT_THAT(options.Get<Executable>(), Eq("exe"));
}

TEST(OptionsTest, ParsesLongFlagEquals) {
  auto options = ParseGivenArgs({"--stderr=foo", "exe"});
  EXPECT_THAT(options.Get<Stderr>(), Eq("foo"));
  EXPECT_THAT(options.Get<Executable>(), Eq("exe"));
}

TEST(OptionsTest, ParsesLongFlagAfterPositional) {
  auto options = ParseGivenArgs({"exe", "--stderr", "foo"});
  EXPECT_THAT(options.Get<Stderr>(), Eq("foo"));
  EXPECT_THAT(options.Get<Executable>(), Eq("exe"));
}

TEST(OptionsTest, ParsesRepeatedFlags) {
  auto options = ParseGivenArgs({"exe", "-E", "foo", "-E", "bar"});
  EXPECT_THAT(options.Get<Executable>(), Eq("exe"));
  const auto &env = options.Get<Environment>();
  ASSERT_THAT(env.size(), Eq(2));
  EXPECT_THAT(env[0].name, Eq("foo"));
  EXPECT_TRUE(!env[0].value.has_value());
  EXPECT_THAT(env[1].name, Eq("bar"));
  EXPECT_TRUE(!env[1].value.has_value());
}

TEST(OptionsTest, ParsesEnv) {
  auto options =
      ParseGivenArgs({"exe", "-E", "foo", "-E", "bar=", "-E", "bar=val"});
  EXPECT_THAT(options.Get<Executable>(), Eq("exe"));
  const auto &env = options.Get<Environment>();
  ASSERT_THAT(env.size(), Eq(3));
  EXPECT_THAT(env[0].name, Eq("foo"));
  EXPECT_TRUE(!env[0].value.has_value());
  EXPECT_THAT(env[1].name, Eq("bar"));
  ASSERT_TRUE(env[1].value.has_value());
  EXPECT_THAT(*env[1].value, Eq(""));
  ASSERT_TRUE(env[2].value.has_value());
  EXPECT_THAT(*env[2].value, Eq("val"));
}

TEST(OptionsTest, ParsesMix) {
  auto options = ParseGivenArgs({"-e", "test", "foo", "-E", "A=", "-E", "C=D",
                                 "arg1", "--", "--arg2", "-e", "bar"});
  EXPECT_THAT(options.Get<Executable>(), Eq("foo"));
  EXPECT_THAT(options.Get<Environment>().size(), Eq(2));
  EXPECT_THAT(options.Get<Stderr>(), Eq("test"));
  const auto &args = options.Get<Args>();
  EXPECT_THAT(args, ElementsAre(Eq("arg1"), Eq("--arg2"), Eq("-e"), Eq("bar")));
}

} // namespace
} // namespace options
