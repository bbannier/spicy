// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>
#include <vector>

#include <hilti/ast/type.h>
#include <hilti/ast/types/unknown.h>

namespace hilti::type {

/*
 * AST node for a `strong_ref<T>` type.
 */
class StrongReference : public Type,
                        trait::isAllocable,
                        trait::isParameterized,
                        trait::isDereferenceable,
                        public trait::isReferenceType {
public:
    StrongReference(Wildcard /*unused*/, Meta m = Meta())
        : Type({type::unknown}, std::move(m)), trait::isReferenceType(&_traits()), _wildcard(true) {}
    StrongReference(Type ct, Meta m = Meta())
        : Type(nodes(std::move(ct)), std::move(m)), trait::isReferenceType(&_traits()) {}
    StrongReference(NodeRef ct, Meta m = Meta())
        : Type(nodes(node::none), std::move(m)), trait::isReferenceType(&_traits()), _type(std::move(ct)) {}

    const Type& dereferencedType() const override {
        if ( _type )
            return _type->as<Type>();
        else
            return children()[0].as<Type>();
    }

    bool operator==(const StrongReference& other) const { return dereferencedType() == other.dereferencedType(); }

    /** Implements the `Type` interface. */
    auto isEqual(const Type& other) const { return node::isEqual(this, other); }
    /** Implements the `Type` interface. */
    bool _isResolved(ResolvedState* rstate) const override {
        return type::detail::isResolved(dereferencedType(), rstate);
    }
    /** Implements the `Type` interface. */
    std::vector<Node> typeParameters() const override { return children(); }
    /** Implements the `Type` interface. */
    bool isWildcard() const override { return _wildcard; }

    /** Implements the `Node` interface. */
    node::Properties properties() const override { return node::Properties{{"type", _type.renderedRid()}}; }

private:
    bool _wildcard = false;
    NodeRef _type;
};

/** AST node for a `weak_ref<T>` type. */
class WeakReference : public Type,
                      trait::isAllocable,
                      trait::isParameterized,
                      trait::isDereferenceable,
                      public trait::isReferenceType {
public:
    WeakReference(Wildcard /*unused*/, Meta m = Meta())
        : Type({type::unknown}, std::move(m)), trait::isReferenceType(&_traits()), _wildcard(true) {}
    WeakReference(Type ct, Meta m = Meta()) : Type({std::move(ct)}, std::move(m)), trait::isReferenceType(&_traits()) {}

    const Type& dereferencedType() const override { return children()[0].as<Type>(); }

    bool operator==(const WeakReference& other) const { return dereferencedType() == other.dereferencedType(); }

    /** Implements the `Type` interface. */
    auto isEqual(const Type& other) const { return node::isEqual(this, other); }
    /** Implements the `Type` interface. */
    bool _isResolved(ResolvedState* rstate) const override {
        return type::detail::isResolved(dereferencedType(), rstate);
    }
    /** Implements the `Type` interface. */
    std::vector<Node> typeParameters() const override { return children(); }
    /** Implements the `Type` interface. */
    bool isWildcard() const override { return _wildcard; }

private:
    bool _wildcard = false;
};

/** AST node for a `val_ref<T>` type. */
class ValueReference : public Type,
                       trait::isAllocable,
                       trait::isParameterized,
                       trait::isDereferenceable,
                       public trait::isReferenceType {
public:
    ValueReference(Wildcard /*unused*/, Meta m = Meta())
        : Type(nodes(type::unknown), std::move(m)), trait::isReferenceType(&_traits()), _wildcard(true) {}
    ValueReference(Type ct, Meta m = Meta())
        : Type(nodes(std::move(ct)), std::move(m)), trait::isReferenceType(&_traits()) {}
    ValueReference(NodeRef ct, Meta m = Meta())
        : Type(nodes(type::unknown), std::move(m)), trait::isReferenceType(&_traits()), _node(std::move(ct)) {}

    const Type& dereferencedType() const override {
        if ( _node )
            return _node->as<Type>();
        else
            return children()[0].as<Type>();
    }

    bool operator==(const ValueReference& other) const { return dereferencedType() == other.dereferencedType(); }

    /** Implements the `Type` interface. */
    auto isEqual(const Type& other) const { return node::isEqual(this, other); }
    /** Implements the `Type` interface. */
    bool _isResolved(ResolvedState* rstate) const override {
        return type::detail::isResolved(dereferencedType(), rstate);
    }
    /** Implements the `Type` interface. */
    std::vector<Node> typeParameters() const override { return children(); }
    /** Implements the `Type` interface. */
    bool isWildcard() const override { return _wildcard; }

    /** Implements the `Node` interface. */
    node::Properties properties() const override { return node::Properties{{"rid", (_node ? _node->rid() : 0U)}}; }

private:
    bool _wildcard = false;
    NodeRef _node;
};

} // namespace hilti::type
