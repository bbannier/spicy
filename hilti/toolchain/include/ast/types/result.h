// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>
#include <vector>

#include <hilti/ast/type.h>
#include <hilti/ast/types/unknown.h>

namespace hilti::type {

/** AST node for a "result" type. */
class Result : public TypeBase, trait::isAllocable, trait::isParameterized, trait::isDereferenceable {
public:
    Result(Wildcard /*unused*/, Meta m = Meta())
        : TypeBase(typeid(Result), {type::unknown}, std::move(m)),
          trait::isAllocable(&_traits()),
          trait::isParameterized(&_traits()),
          trait::isDereferenceable(&_traits()),
          _wildcard(true) {}
    Result(Type ct, Meta m = Meta())
        : TypeBase(typeid(Result), {std::move(ct)}, std::move(m)),
          trait::isAllocable(&_traits()),
          trait::isParameterized(&_traits()),
          trait::isDereferenceable(&_traits()) {}

    const Type& dereferencedType() const override { return children()[0].as<Type>(); }

    bool operator==(const Result& other) const { return dereferencedType() == other.dereferencedType(); }

    /** Implements the `Type` interface. */
    bool isEqual(const Type& other) const override { return node::isEqual(this, other); }
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
