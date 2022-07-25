// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>

#include <hilti/ast/type.h>

namespace hilti::type {

/** AST node for a regexp type. */
class RegExp : public Type, trait::isAllocable, public trait::isRuntimeNonTrivial {
public:
    RegExp(Meta m = Meta())
        : Type(std::move(m)), trait::isAllocable(&_traits()), trait::isRuntimeNonTrivial(&_traits()) {}

    bool operator==(const RegExp& /* other */) const { return true; }

    /** Implements the `Type` interface. */
    auto isEqual(const Type& other) const { return node::isEqual(this, other); }
    /** Implements the `Type` interface. */
    bool _isResolved(ResolvedState* rstate) const override { return true; }
    /** Implements the `Node` interface. */
    node::Properties properties() const override { return node::Properties{}; }
};

} // namespace hilti::type
