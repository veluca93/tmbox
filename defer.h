#pragma once
#include <utility>

template <typename Fn> class Defer {
public:
  Defer(Fn &&fun) : fun(std::move(fun)) {}
  ~Defer() { fun(); }
  Defer(const Defer &) = delete;
  Defer(Defer &&) = delete;
  Defer &operator=(const Defer &) = delete;
  Defer &operator=(Defer &&) = delete;

private:
  Fn fun;
};
