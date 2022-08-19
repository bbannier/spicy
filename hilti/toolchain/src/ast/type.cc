// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#include <hilti/ast/type.h>
#include <hilti/ast/types/auto.h>
#include <hilti/ast/types/unknown.h>
#include <hilti/ast/types/unresolved-id.h>

using namespace hilti;

bool type::isResolved(const Type& t) {
    ResolvedState rstate;
    return true; // FIXME(bbannier)
}

bool type::detail::isResolved(const hilti::Type& t, ResolvedState* rstate) {
    if ( ! rstate )
        return type::isResolved(t);

    if ( type::isParameterized(t) ) {
        const auto identity = t.identity();
        if ( rstate->count(identity) )
            return true;

        rstate->insert(identity);
    }

    return t._isResolved(rstate);
}

void type::detail::applyPruneWalk(hilti::Type& t) {
    // We prune at the types that have an ID, as only they can create cycles.
    if ( t.typeID() ) {
        t.addFlag(type::Flag::PruneWalk);
        return;
    }

    for ( auto&& c : t.children() ) {
        if ( auto x = c.tryAs<hilti::Type>() )
            applyPruneWalk(const_cast<hilti::Type&>(*x));
    }
}
