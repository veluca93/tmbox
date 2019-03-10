#include "tests/util.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

namespace {

using testing::Eq;

TEST(ProcessTest, SigAbortWorks) {
  auto results = RunProgramWithOptions({"-r", "/"}, "abort", {""});
  EXPECT_FALSE(results.error);
  EXPECT_EQ(results.message, "");
  EXPECT_THAT(results.signal, Eq(SIGABRT));
}

} // namespace
