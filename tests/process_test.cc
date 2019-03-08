#include "tests/util.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

namespace {

using testing::Eq;

TEST(ProcessTest, TestThreadsWork) {
  auto results = RunProgramWithOptions({""}, "thread", {""});
  EXPECT_FALSE(results.error);
  EXPECT_THAT(results.signal, Eq(0));
}

TEST(ProcessTest, TestThreadsWorkP) {
  auto results = RunProgramWithOptions({"-p"}, "thread", {""});
  EXPECT_FALSE(results.error);
  EXPECT_THAT(results.signal, Eq(0));
}

TEST(ProcessTest, TestForkBlocked) {
  auto results = RunProgramWithOptions({""}, "fork", {""});
  EXPECT_FALSE(results.error);
  EXPECT_THAT(results.signal, Eq(SIGSYS));
}

TEST(ProcessTest, TestForkWorksP) {
  auto results = RunProgramWithOptions({"-p"}, "fork", {""});
  EXPECT_FALSE(results.error);
  EXPECT_THAT(results.signal, Eq(0));
}

TEST(ProcessTest, TestVforkBlocked) {
  auto results = RunProgramWithOptions({""}, "vfork", {""});
  EXPECT_FALSE(results.error);
  EXPECT_THAT(results.signal, Eq(SIGSYS));
}

TEST(ProcessTest, TestVforkWorksP) {
  auto results = RunProgramWithOptions({"-p"}, "vfork", {""});
  EXPECT_FALSE(results.error);
  EXPECT_THAT(results.signal, Eq(0));
}

} // namespace
