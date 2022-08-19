// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>

#include <hilti/ast/type.h>

namespace hilti::type {

/** AST node for a port type. */
class Port : public TypeBase, trait::isAllocable {
public:
    Port(Meta m = Meta()) : TypeBase(typeid(Port), std::move(m)), trait::isAllocable(&_traits()) {}

    bool operator==(const Port& /* other */) const { return true; }

    /** Implements the `Type` interface. */
    bool isEqual(const Type& other) const override { return node::isEqual(this, other); }
    /** Implements the `Type` interface. */
    bool _isResolved(ResolvedState* rstate) const override { return true; }
    /** Implements the `Node` interface. */
    node::Properties properties() const override { return node::Properties{}; }
};

} // namespace hilti::type
