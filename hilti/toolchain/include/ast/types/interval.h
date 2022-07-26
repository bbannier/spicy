// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>

#include <hilti/ast/type.h>

namespace hilti::type {

/** AST node for an interval type. */
class Interval : public Type, trait::isAllocable {
public:
    Interval(Meta m = Meta()) : Type(typeid(Interval), std::move(m)), trait::isAllocable(&_traits()) {}

    bool operator==(const Interval& /* other */) const { return true; }

    /** Implements the `Type` interface. */
    auto isEqual(const Type& other) const { return node::isEqual(this, other); }
    /** Implements the `Type` interface. */
    bool _isResolved(ResolvedState* rstate) const override { return true; }
};

} // namespace hilti::type
