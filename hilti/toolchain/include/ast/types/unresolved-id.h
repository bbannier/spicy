// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>

#include <hilti/ast/declaration.h>
#include <hilti/ast/declarations/type.h>
#include <hilti/ast/id.h>
#include <hilti/ast/node-ref.h>
#include <hilti/ast/type.h>

namespace hilti::type {

/** AST node for an unresolved type ID. */
class UnresolvedID : public Type {
public:
    UnresolvedID(::hilti::ID id, Meta m = Meta()) : Type(typeid(UnresolvedID), {std::move(id)}, std::move(m)) {}

    const auto& id() const { return child<::hilti::ID>(0); }

    bool operator==(const UnresolvedID& other) const { return id() == other.id(); }

    // Type interface.
    auto isEqual(const Type& other) const { return node::isEqual(this, other); }
    /** Implements the `Type` interface. */
    bool _isResolved(ResolvedState* rstate) const override { return false; }
};

} // namespace hilti::type
