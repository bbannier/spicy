// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>

#include <hilti/ast/type.h>
#include <hilti/ast/types/unknown.h>

namespace hilti::type {

/** AST node for an "optional" type. */
class Optional : public TypeBase, trait::isParameterized, trait::isDereferenceable {
public:
    Optional(Wildcard /*unused*/, Meta m = Meta()) : TypeBase({type::unknown}, std::move(m)), _wildcard(true) {}
    Optional(Type ct, Meta m = Meta()) : TypeBase({std::move(ct)}, std::move(m)) {}

    const Type& dereferencedType() const { return children()[0].as<Type>(); }

    bool operator==(const Optional& other) const { return dereferencedType() == other.dereferencedType(); }

    /** Implements the `Type` interface. */
    auto isEqual(const Type& other) const { return node::isEqual(this, other); }
    /** Implements the `Type` interface. */
    auto _isResolved(ResolvedState* rstate) const { return type::detail::isResolved(dereferencedType(), rstate); }
    /** Implements the `Type` interface. */
    auto typeParameters() const { return children(); }
    /** Implements the `Type` interface. */
    auto isWildcard() const { return _wildcard; }

    /** Implements the `Node` interface. */
    auto properties() const { return node::Properties{}; }

    bool _isAllocable() const override { return true; }

private:
    bool _wildcard = false;
};

} // namespace hilti::type
