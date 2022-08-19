// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>
#include <vector>

#include <hilti/ast/type.h>

namespace hilti::type {

/** AST node for an `exception` type. */
class Exception : public TypeBase, trait::isAllocable, trait::isParameterized {
public:
    Exception(Meta m = Meta())
        : TypeBase(typeid(Exception), {node::none}, std::move(m)),
          trait::isAllocable(&_traits()),
          trait::isParameterized(&_traits()) {}
    Exception(Type base, Meta m = Meta())
        : TypeBase(typeid(Exception), {std::move(base)}, std::move(m)),
          trait::isAllocable(&_traits()),
          trait::isParameterized(&_traits()) {}
    Exception(Wildcard /*unused*/, Meta m = Meta())
        : TypeBase(typeid(Exception), {node::none}, std::move(m)),
          trait::isAllocable(&_traits()),
          trait::isParameterized(&_traits()),
          _wildcard(true) {}

    hilti::optional_ref<const Type> baseType() const { return children()[0].tryAs<Type>(); }

    bool operator==(const Exception& other) const { return baseType() == other.baseType(); }

    /** Implements the `Type` interface. */
    bool isEqual(const Type& other) const override { return node::isEqual(this, other); }
    /** Implements the `Type` interface. */
    bool _isResolved(ResolvedState* rstate) const override {
        return baseType().has_value() ? type::detail::isResolved(baseType(), rstate) : true;
    }
    /** Implements the `Type` interface. */
    std::vector<Node> typeParameters() const override { return children(); }
    /** Implements the `Type` interface. */
    bool isWildcard() const override { return _wildcard; }

private:
    bool _wildcard = false;
};

} // namespace hilti::type
