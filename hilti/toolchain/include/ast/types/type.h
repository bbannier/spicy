// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>
#include <vector>

#include <hilti/ast/type.h>
#include <hilti/ast/types/any.h>

namespace hilti::type {

/** AST node for a type representing a type value. */
class Type_ : public TypeBase, trait::isParameterized {
public:
    Type_(Type t, Meta m = Meta())
        : TypeBase(typeid(Type_), nodes(std::move(t)), std::move(m)), trait::isParameterized(&_traits()) {}
    Type_(Wildcard /*unused*/, Meta m = Meta())
        : TypeBase(typeid(Type_), nodes(type::Any()), std::move(m)),
          trait::isParameterized(&_traits()),
          _wildcard(true) {}

    const auto& typeValue() const { return child<Type>(0); }

    bool operator==(const Type_& other) const { return typeValue() == other.typeValue(); }

    /** Implements the `Type` interface. */
    bool isEqual(const Type& other) const override { return node::isEqual(this, other); }
    /** Implements the `Type` interface. */
    bool _isResolved(ResolvedState* rstate) const override { return type::detail::isResolved(typeValue(), rstate); }
    /** Implements the `Type` interface. */
    std::vector<Node> typeParameters() const override { return children(); }
    /** Implements the `Type` interface. */
    bool isWildcard() const override { return _wildcard; }

private:
    bool _wildcard = false;
};

} // namespace hilti::type
