// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>

#include <hilti/ast/type.h>
#include <hilti/ast/types/integer.h>

namespace hilti::type {

namespace stream {

/** AST node for a stream iterator type. */
class Iterator : public Type,
                 trait::isIterator,
                 trait::isDereferenceable,
                 trait::isAllocable,
                 public trait::isMutable,
                 public trait::isRuntimeNonTrivial {
public:
    Iterator(Meta m = Meta())
        : Type(nodes(type::UnsignedInteger(8)), std::move(m)),
          trait::isDereferenceable(&_traits()),
          trait::isAllocable(&_traits()),
          trait::isMutable(&_traits()),
          trait::isRuntimeNonTrivial(&_traits()) {}

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

/** AST node for a stream view type. */
class View : public Type, trait::isView, trait::isAllocable, public trait::isRuntimeNonTrivial {
public:
    View(const Meta& m = Meta())
        : Type(nodes(stream::Iterator(m)), m),
          trait::isView(&_traits()),
          trait::isAllocable(&_traits()),
          trait::isRuntimeNonTrivial(&_traits()) {}

    bool operator==(const View& /* other */) const { return true; }

    /** Implements the `Type` interface. */
    auto isEqual(const Type& other) const { return node::isEqual(this, other); }
    /** Implements the `Type` interface. */
    bool _isResolved(ResolvedState* rstate) const override { return true; }
    /** Implements the `Type` interface. */
    const Type& elementType() const override {
        return dynamic_cast<const trait::isDereferenceable&>(iteratorType(true)).dereferencedType();
    }
    /** Implements the `Type` interface. */
    const Type& iteratorType(bool /* const_ */) const override { return child<Type>(0); }
    /** Implements the `Node` interface. */
    node::Properties properties() const override { return node::Properties{}; }
};

} // namespace stream

/** AST node for a stream type. */
class Stream : public Type,
               trait::isAllocable,
               public trait::isMutable,
               trait::isIterable,
               trait::isViewable,
               public trait::isRuntimeNonTrivial {
public:
    Stream(const Meta& m = Meta())
        : Type(nodes(stream::View(m)), m),
          trait::isAllocable(&_traits()),
          trait::isMutable(&_traits()),
          trait::isIterable(&_traits()),
          trait::isRuntimeNonTrivial(&_traits()) {}

    bool operator==(const Stream& /* other */) const { return true; }

    /** Implements the `Type` interface. */
    auto isEqual(const Type& other) const { return node::isEqual(this, other); }
    /** Implements the `Type` interface. */
    bool _isResolved(ResolvedState* rstate) const override { return true; }
    /** Implements the `Type` interface. */
    const Type& elementType() const override {
        return dynamic_cast<const trait::isDereferenceable&>(iteratorType(true)).dereferencedType();
    }
    /** Implements the `Type` interface. */
    const Type& iteratorType(bool /* const_ */) const override {
        return dynamic_cast<const trait::isIterable&>(viewType()).iteratorType(true);
    }
    /** Implements the `Type` interface. */
    const Type& viewType() const override { return child<Type>(0); }
    /** Implements the `Node` interface. */
    node::Properties properties() const override { return node::Properties{}; }
};

namespace detail::stream {
inline Node element_type = Node(type::UnsignedInteger(8, Location()));
} // namespace detail::stream

} // namespace hilti::type
