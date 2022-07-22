// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>
#include <vector>

#include <hilti/ast/type.h>
#include <hilti/ast/types/unknown.h>

namespace hilti::type {

namespace set {

/** AST node for a set iterator type. */
class Iterator : public Type,
                 trait::isIterator,
                 trait::isDereferenceable,
                 trait::isAllocable,
                 trait::isMutable,
                 trait::isRuntimeNonTrivial,
                 trait::isParameterized {
public:
    Iterator(Type etype, bool const_, Meta m = Meta()) : Type(nodes(std::move(etype)), std::move(m)), _const(const_) {}
    Iterator(Wildcard /*unused*/, bool const_ = true, Meta m = Meta())
        : Type(nodes(type::unknown), std::move(m)), _wildcard(true), _const(const_) {}

    /** Returns true if the container elements aren't modifiable. */
    bool isConstant() const { return _const; }

    /** Implements the `Type` interface. */
    auto isEqual(const Type& other) const { return node::isEqual(this, other); }
    /** Implements the `Type` interface. */
    bool _isResolved(ResolvedState* rstate) const override {
        return type::detail::isResolved(dereferencedType(), rstate);
    }
    /** Implements the `Type` interface. */
    const Type& dereferencedType() const override { return child<Type>(0); }
    /** Implements the `Type` interface. */
    bool isWildcard() const override { return _wildcard; }
    /** Implements the `Type` interface. */
    std::vector<Node> typeParameters() const override { return children(); }
    /** Implements the `Node` interface. */
    node::Properties properties() const override { return node::Properties{{"const", _const}}; }

    bool operator==(const Iterator& other) const { return dereferencedType() == other.dereferencedType(); }

private:
    bool _wildcard = false;
    bool _const = false;
};

} // namespace set

/** AST node for a set type. */
class Set : public Type,
            trait::isAllocable,
            trait::isMutable,
            trait::isIterable,
            trait::isRuntimeNonTrivial,
            trait::isParameterized {
public:
    Set(const Type& t, const Meta& m = Meta())
        : Type(nodes(set::Iterator(t, true, m), set::Iterator(t, false, m)), m) {}
    Set(Wildcard /*unused*/, const Meta& m = Meta())
        : Type(nodes(set::Iterator(Wildcard{}, true, m), set::Iterator(Wildcard{}, false, m)), m), _wildcard(true) {}

    /** Implements the `Type` interface. */
    auto isEqual(const Type& other) const { return node::isEqual(this, other); }
    /** Implements the `Type` interface. */
    bool _isResolved(ResolvedState* rstate) const override {
        return type::detail::isResolved(iteratorType(true), rstate) &&
               type::detail::isResolved(iteratorType(false), rstate);
    }
    /** Implements the `Type` interface. */
    const Type& elementType() const override { return child<set::Iterator>(0).dereferencedType(); }
    /** Implements the `Type` interface. */
    const Type& iteratorType(bool const_) const override { return const_ ? child<Type>(0) : child<Type>(1); }
    /** Implements the `Type` interface. */
    bool isWildcard() const override { return _wildcard; }
    /** Implements the `Type` interface. */
    std::vector<Node> typeParameters() const override { return children(); }

    bool operator==(const Set& other) const { return elementType() == other.elementType(); }

private:
    bool _wildcard = false;
};

} // namespace hilti::type
