// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#if defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wtautological-overlap-compare"
#pragma clang diagnostic ignored "-Wdeprecated-literal-operator"
#elif defined(__GNUC__)
// Note that clang #defines __GNUC__ as well.
#pragma GCC diagnostic push
#endif

#include <hilti/rt/3rdparty/nlohmann/json.hpp>

#if defined(__clang__)
#pragma clang diagnostic pop
#elif defined(__GNUC__)
#pragma GCC diagnostic pop
#endif
