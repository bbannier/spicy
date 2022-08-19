// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>

#include <hilti/ast/type.h>

namespace hilti::type {

/** AST node for a address type. */
class Address : public TypeBase, trait::isAllocable {
public:
    Address(Meta m = Meta()) : TypeBase(typeid(Address), std::move(m)), trait::isAllocable(&_traits()) {}

    bool operator==(const Address& /* other */) const { return true; }

    /** Implements the `Type` interface. */
    bool isEqual(const Type& other) const override { return node::isEqual(this, other); }
    /** Implements the `Type` interface. */
    bool _isResolved(ResolvedState* rstate) const override { return true; }
    /** Implements the `Node` interface. */
    node::Properties properties() const override { return node::Properties{}; }
};

} // namespace hilti::type
