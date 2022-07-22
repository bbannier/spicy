// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>

#include <hilti/ast/type.h>
#include <hilti/ast/types/integer.h>

namespace hilti::type {

namespace bytes {

/** AST node for a list iterator type. */
class Iterator : public Type,
                 trait::isIterator,
                 trait::isDereferenceable,
                 trait::isAllocable,
                 trait::isMutable,
                 trait::isRuntimeNonTrivial {
public:
    Iterator(Meta m = Meta()) : Type(nodes(Type(type::UnsignedInteger(8))), std::move(m)) {}

    bool operator==(const Iterator& /* other */) const { return true; }

    /** Implements the `Type` interface. */
    auto isEqual(const Type& other) const { return node::isEqual(this, other); }
    /** Implements the `Type` interface. */
    bool _isResolved(ResolvedState* rstate) const override { return true; }
    /** Implements the `Type` interface. */
    const Type& dereferencedType() const override { return child<Type>(0); }
    /** Implements the `Node` interface. */
    node::Properties properties() const override { return node::Properties{}; }
};

} // namespace bytes

/** AST node for a bytes type. */
class Bytes : public Type, trait::isAllocable, trait::isMutable, trait::isIterable, trait::isRuntimeNonTrivial {
public:
    Bytes(const Meta& m = Meta()) : Type(nodes(Type(type::UnsignedInteger(8)), Type(bytes::Iterator(m))), m) {}

    bool operator==(const Bytes& /* other */) const { return true; }

    /** Implements the `Type` interface. */
    auto isEqual(const Type& other) const { return node::isEqual(this, other); }
    /** Implements the `Type` interface. */
    bool _isResolved(ResolvedState* rstate) const override { return true; }
    /** Implements the `Type` interface. */
    const Type& elementType() const override { return child<Type>(0); }

    /** Implements the `Type` interface. */
    const Type& iteratorType(bool /* const */) const override { return child<Type>(1); }
    /** Implements the `Node` interface. */
    node::Properties properties() const override { return node::Properties{}; }
};

} // namespace hilti::type
