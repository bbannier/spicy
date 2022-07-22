// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>
#include <vector>

#include <hilti/ast/type.h>
#include <hilti/ast/types/unknown.h>

namespace hilti::type {

/** AST node for an "optional" type. */
class Optional : public Type, trait::isAllocable, trait::isParameterized, trait::isDereferenceable {
public:
    Optional(Wildcard /*unused*/, Meta m = Meta()) : Type({type::unknown}, std::move(m)), _wildcard(true) {}
    Optional(Type ct, Meta m = Meta()) : Type({std::move(ct)}, std::move(m)) {}

    const Type& dereferencedType() const override { return children()[0].as<Type>(); }

    bool operator==(const Optional& other) const { return dereferencedType() == other.dereferencedType(); }

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

} // namespace hilti::type
