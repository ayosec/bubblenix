#pragma once

#define _GNU_SOURCE

#include <stdbool.h>
#include <stdio.h>

struct Options {
  bool allow_clone3;
  bool allow_tracing;
  bool allow_fsync;
  FILE *output;
};
