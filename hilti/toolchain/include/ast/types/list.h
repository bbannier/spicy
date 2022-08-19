// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>
#include <vector>

#include <hilti/ast/type.h>
#include <hilti/ast/types/unknown.h>

namespace hilti::type {

namespace list {

/** AST node for a list iterator type. */
class Iterator : public TypeBase,
                 trait::isIterator,
                 trait::isDereferenceable,
                 trait::isAllocable,
                 public trait::isMutable,
                 public trait::isRuntimeNonTrivial,
                 trait::isParameterized {
public:
    Iterator(Type etype, bool const_, Meta m = Meta())
        : TypeBase(typeid(Iterator), nodes(std::move(etype)), std::move(m)),
          trait::isIterator(&_traits()),
          trait::isDereferenceable(&_traits()),
          trait::isAllocable(&_traits()),
          trait::isMutable(&_traits()),
          trait::isRuntimeNonTrivial(&_traits()),
          trait::isParameterized(&_traits()),
          _const(const_) {}
    Iterator(Wildcard /*unused*/, bool const_ = true, Meta m = Meta())
        : TypeBase(typeid(Iterator), nodes(type::unknown), std::move(m)),
          trait::isIterator(&_traits()),
          trait::isDereferenceable(&_traits()),
          trait::isAllocable(&_traits()),
          trait::isMutable(&_traits()),
          trait::isRuntimeNonTrivial(&_traits()),
          trait::isParameterized(&_traits()),
          _wildcard(true),
          _const(const_) {}

    /** Returns true if the container elements aren't modifiable. */
    bool isConstant() const { return _const; }

    /** Implements the `Type` interface. */
    bool isEqual(const Type& other) const override { return node::isEqual(this, other); }
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

} // namespace list

/** AST node for a list type. */
class List : public TypeBase,
             trait::isAllocable,
             public trait::isMutable,
             trait::isIterable,
             public trait::isRuntimeNonTrivial,
             trait::isParameterized {
public:
    List(const Type& t, const Meta& m = Meta())
        : TypeBase(typeid(List), nodes(list::Iterator(t, true, m), list::Iterator(t, false, m)), m),
          trait::isAllocable(&_traits()),
          trait::isMutable(&_traits()),
          trait::isIterable(&_traits()),
          trait::isRuntimeNonTrivial(&_traits()),
          trait::isParameterized(&_traits()) {}
    List(Wildcard /*unused*/, const Meta& m = Meta())
        : TypeBase(typeid(List), nodes(list::Iterator(Wildcard{}, true, m), list::Iterator(Wildcard{}, false, m)), m),
          trait::isAllocable(&_traits()),
          trait::isMutable(&_traits()),
          trait::isIterable(&_traits()),
          trait::isRuntimeNonTrivial(&_traits()),
          trait::isParameterized(&_traits()),
          _wildcard(true) {}

    /** Implements the `Type` interface. */
    bool isEqual(const Type& other) const override { return node::isEqual(this, other); }
    /** Implements the `Type` interface. */
    bool _isResolved(ResolvedState* rstate) const override {
        return type::detail::isResolved(iteratorType(true), rstate) &&
               type::detail::isResolved(iteratorType(false), rstate);
    }
    /** Implements the `Type` interface. */
    const Type& elementType() const override { return child<list::Iterator>(0).dereferencedType(); }
    /** Implements the `Type` interface. */
    const Type& iteratorType(bool const_) const override { return const_ ? child<Type>(0) : child<Type>(1); }
    /** Implements the `Type` interface. */
    bool isWildcard() const override { return _wildcard; }
    /** Implements the `Type` interface. */
    std::vector<Node> typeParameters() const override { return children(); }

    bool operator==(const List& other) const { return elementType() == other.elementType(); }

private:
    bool _wildcard = false;
};

} // namespace hilti::type
