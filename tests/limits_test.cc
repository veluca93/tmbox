#include "tests/util.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

namespace {

using testing::Eq;

TEST(ProcessTest, TestCpuLimitOk) {
  auto results =
      RunProgramWithOptions({"-r", "/", "-t", "1"}, "busywait", {"0.1"});
  EXPECT_FALSE(results.error);
  EXPECT_EQ(results.message, "");
  EXPECT_THAT(results.signal, Eq(0));
}

TEST(ProcessTest, TestCpuLimitNotOk) {
  auto results =
      RunProgramWithOptions({"-r", "/", "-t", "1"}, "busywait", {"2"});
  EXPECT_FALSE(results.error);
  EXPECT_EQ(results.message, "");
  EXPECT_THAT(results.signal, Eq(SIGKILL));
}

TEST(ProcessTest, TestWallLimitOk) {
  auto results = RunProgramWithOptions({"-r", "/", "-w", "1"}, "wait", {"0.1"});
  EXPECT_FALSE(results.error);
  EXPECT_EQ(results.message, "");
  EXPECT_THAT(results.signal, Eq(0));
}

TEST(ProcessTest, TestWallLimitNotOk) {
  auto results = RunProgramWithOptions({"-r", "/", "-w", "1"}, "wait", {"2"});
  EXPECT_FALSE(results.error);
  EXPECT_EQ(results.message, "");
  EXPECT_THAT(results.signal, Eq(SIGKILL));
  EXPECT_TRUE(results.killed_by_sandbox);
}

TEST(ProcessTest, TestMemoryLimitOk) {
  auto results =
      RunProgramWithOptions({"-r", "/", "-m", "65536"}, "malloc", {"1"});
  EXPECT_FALSE(results.error);
  EXPECT_EQ(results.message, "");
  EXPECT_THAT(results.signal, Eq(0));
}

TEST(ProcessTest, TestMemoryLimitNotOk) {
  auto results =
      RunProgramWithOptions({"-r", "/", "-m", "65536"}, "malloc", {"128"});
  EXPECT_FALSE(results.error);
  EXPECT_EQ(results.message, "");
  EXPECT_THAT(results.signal, Eq(SIGSEGV));
}

} // namespace
