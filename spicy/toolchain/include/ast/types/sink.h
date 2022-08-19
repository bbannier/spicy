// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>

#include <hilti/ast/type.h>

namespace spicy::type {

/** AST node for a Sink type. */
class Sink : public hilti::TypeBase, hilti::type::trait::isAllocable {
public:
    Sink(hilti::Meta m = hilti::Meta())
        : TypeBase(typeid(Sink), std::move(m)), hilti::type::trait::isAllocable(&_traits()) {}

    bool operator==(const Sink& /* other */) const { return true; }

    /** Implements the `Type` interface. */
    bool isEqual(const hilti::Type& other) const override { return hilti::node::isEqual(this, other); }
    /** Implements the `Type` interface. */
    bool _isResolved(hilti::type::ResolvedState* rstate) const override { return true; }
};

} // namespace spicy::type
