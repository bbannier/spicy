// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>

#include <hilti/ast/type.h>

namespace hilti::type {

/** AST node for a bool type. */
class Bool : public Type, trait::isAllocable {
public:
    Bool(Meta m = Meta()) : Type(typeid(Bool), std::move(m)), trait::isAllocable(&_traits()) {}

    bool operator==(const Bool& /* other */) const { return true; }

    /** Implements the `Type` interface. */
    auto isEqual(const Type& other) const { return node::isEqual(this, other); }
    /** Implements the `Type` interface. */
    bool _isResolved(ResolvedState* rstate) const override { return true; }
};

} // namespace hilti::type
