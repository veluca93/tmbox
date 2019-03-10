#include "tests/util.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

namespace {

using testing::Eq;

TEST(ProcessTest, TestThreadsWork) {
  auto results = RunProgramWithOptions({"-r", "/"}, "thread", {""});
  EXPECT_FALSE(results.error);
  EXPECT_EQ(results.message, "");
  EXPECT_THAT(results.signal, Eq(0));
}

TEST(ProcessTest, TestThreadsWorkP) {
  auto results = RunProgramWithOptions({"-r", "/", "-p"}, "thread", {""});
  EXPECT_FALSE(results.error);
  EXPECT_EQ(results.message, "");
  EXPECT_THAT(results.signal, Eq(0));
}

TEST(ProcessTest, TestForkBlocked) {
  auto results = RunProgramWithOptions({"-r", "/"}, "fork", {""});
  EXPECT_FALSE(results.error);
  EXPECT_EQ(results.message, "");
  EXPECT_THAT(results.signal, Eq(SIGSYS));
}

TEST(ProcessTest, TestForkWorksP) {
  auto results = RunProgramWithOptions({"-r", "/", "-p"}, "fork", {""});
  EXPECT_FALSE(results.error);
  EXPECT_EQ(results.message, "");
  EXPECT_THAT(results.signal, Eq(0));
}

TEST(ProcessTest, TestVforkBlocked) {
  auto results = RunProgramWithOptions({"-r", "/"}, "vfork", {""});
  EXPECT_FALSE(results.error);
  EXPECT_EQ(results.message, "");
  EXPECT_THAT(results.signal, Eq(SIGSYS));
}

TEST(ProcessTest, TestVforkWorksP) {
  auto results = RunProgramWithOptions({"-r", "/", "-p"}, "vfork", {""});
  EXPECT_FALSE(results.error);
  EXPECT_EQ(results.message, "");
  EXPECT_THAT(results.signal, Eq(0));
}

} // namespace
