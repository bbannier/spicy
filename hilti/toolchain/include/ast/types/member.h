// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>
#include <vector>

#include <hilti/ast/id.h>
#include <hilti/ast/node-ref.h>
#include <hilti/ast/type.h>

namespace hilti::type {

/** AST node for a type representing a member of another type. */
class Member : public TypeBase, trait::isParameterized {
public:
    Member(Wildcard /*unused*/, Meta m = Meta())
        : TypeBase(typeid(Member), {ID("<wildcard>")}, std::move(m)),
          trait::isParameterized(&_traits()),
          _wildcard(true) {}
    Member(::hilti::ID id, Meta m = Meta())
        : TypeBase(typeid(Member), {std::move(id)}, std::move(m)), trait::isParameterized(&_traits()) {}

    const auto& id() const { return child<::hilti::ID>(0); }

    bool operator==(const Member& other) const { return id() == other.id(); }

    /** Implements the `Type` interface. */
    bool isEqual(const Type& other) const override { return node::isEqual(this, other); }
    /** Implements the `Type` interface. */
    bool _isResolved(ResolvedState* rstate) const override { return true; }
    /** Implements the `Type` interface. */
    std::vector<Node> typeParameters() const override { return std::vector<Node>{id()}; }
    /** Implements the `Type` interface. */
    bool isWildcard() const override { return _wildcard; }

private:
    bool _wildcard = false;
};

} // namespace hilti::type
