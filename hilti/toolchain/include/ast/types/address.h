// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>

#include <hilti/ast/type.h>

namespace hilti::type {

/** AST node for a address type. */
class Address : public Type, trait::isAllocable {
public:
    Address(Meta m = Meta()) : Type(std::move(m)) {}

    bool operator==(const Address& /* other */) const { return true; }

    /** Implements the `Type` interface. */
    auto isEqual(const Type& other) const { return node::isEqual(this, other); }
    /** Implements the `Type` interface. */
    bool _isResolved(ResolvedState* rstate) const { return true; }
    /** Implements the `Node` interface. */
    auto properties() const { return node::Properties{}; }
};

} // namespace hilti::type
