// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>

#include <hilti/ast/type.h>
#include <hilti/ast/types/integer.h>

namespace hilti::type {

namespace stream {

/** AST node for a stream iterator type. */
class Iterator : public TypeBase,
                 trait::isIterator,
                 trait::isDereferenceable,
                 trait::isAllocable,
                 trait::isMutable,
                 trait::isRuntimeNonTrivial {
public:
    Iterator(Meta m = Meta()) : TypeBase(nodes(type::UnsignedInteger(8)), std::move(m)) {}

    bool operator==(const Iterator& /* other */) const { return true; }

    /** Implements the `Type` interface. */
    auto isEqual(const Type& other) const { return node::isEqual(this, other); }
    /** Implements the `Type` interface. */
    auto _isResolved(ResolvedState* rstate) const { return true; }
    /** Implements the `Type` interface. */
    const Type& dereferencedType() const override { return child<Type>(0); }
    /** Implements the `Node` interface. */
    auto properties() const { return node::Properties{}; }
};

/** AST node for a stream view type. */
class View : public TypeBase, trait::isView, trait::isAllocable, trait::isRuntimeNonTrivial {
public:
    View(const Meta& m = Meta()) : TypeBase(nodes(stream::Iterator(m)), m) {}

    bool operator==(const View& /* other */) const { return true; }

    /** Implements the `Type` interface. */
    auto isEqual(const Type& other) const { return node::isEqual(this, other); }
    /** Implements the `Type` interface. */
    auto _isResolved(ResolvedState* rstate) const { return true; }
    /** Implements the `Type` interface. */
    const Type& elementType() const override {
        return dynamic_cast<const trait::isDereferenceable&>(iteratorType(true)).dereferencedType();
    }
    /** Implements the `Type` interface. */
    const Type& iteratorType(bool /* const_ */) const override { return child<Type>(0); }
    /** Implements the `Node` interface. */
    auto properties() const { return node::Properties{}; }
};

} // namespace stream

/** AST node for a stream type. */
class Stream : public TypeBase,
               trait::isAllocable,
               trait::isMutable,
               trait::isIterable,
               trait::isViewable,
               trait::isRuntimeNonTrivial {
public:
    Stream(const Meta& m = Meta()) : TypeBase(nodes(stream::View(m)), m) {}

    bool operator==(const Stream& /* other */) const { return true; }

    /** Implements the `Type` interface. */
    auto isEqual(const Type& other) const { return node::isEqual(this, other); }
    /** Implements the `Type` interface. */
    auto _isResolved(ResolvedState* rstate) const { return true; }
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
    auto properties() const { return node::Properties{}; }
};

namespace detail::stream {
inline Node element_type = Node(type::UnsignedInteger(8, Location()));
} // namespace detail::stream

} // namespace hilti::type
