// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>

#include <hilti/ast/type.h>

namespace hilti::type {

/** AST node for an "auto" type. */
class Auto : public Type, type::trait::isAllocable {
public:
    bool operator==(const Auto& /* other */) const { return true; }

    /** Implements the `Type` interface. */
    auto isEqual(const Type& other) const { return node::isEqual(this, other); }
    /** Implements the `Type` interface. */
    bool _isResolved(ResolvedState* rstate) const override { return false; }

    /**
     * Wrapper around constructor so that we can make it private. Don't use
     * this, use the singleton `type::auto_` instead.
     */
    static Auto create(Meta m = Meta()) { return Auto(std::move(m)); }

private:
    Auto(Meta m = Meta()) : Type(typeid(Auto), std::move(m)), trait::isAllocable(&_traits()) {}
};

/** Singleton. */
static const Type auto_ = Auto::create(Location("<singleton>"));

} // namespace hilti::type
