// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>
#include <vector>

#include <hilti/ast/type.h>

namespace hilti::type {

/** AST node for an `exception` type. */
class Exception : public Type, trait::isAllocable, trait::isParameterized {
public:
    Exception(Meta m = Meta()) : Type({node::none}, std::move(m)) {}
    Exception(Type base, Meta m = Meta()) : Type({std::move(base)}, std::move(m)) {}
    Exception(Wildcard /*unused*/, Meta m = Meta()) : Type({node::none}, std::move(m)), _wildcard(true) {}

    hilti::optional_ref<const Type> baseType() const { return children()[0].tryAs<Type>(); }

    bool operator==(const Exception& other) const { return baseType() == other.baseType(); }

    /** Implements the `Type` interface. */
    auto isEqual(const Type& other) const { return node::isEqual(this, other); }
    /** Implements the `Type` interface. */
    bool _isResolved(ResolvedState* rstate) const override {
        return baseType().has_value() ? type::detail::isResolved(baseType(), rstate) : true;
    }
    /** Implements the `Type` interface. */
    std::vector<Node> typeParameters() const override { return children(); }
    /** Implements the `Type` interface. */
    bool isWildcard() const override { return _wildcard; }
    /** Implements the `Node` interface. */
    auto properties() const { return node::Properties{}; }

private:
    bool _wildcard = false;
};

} // namespace hilti::type
