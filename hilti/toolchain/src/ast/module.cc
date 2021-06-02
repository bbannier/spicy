// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#include <algorithm>

#include <hilti/ast/detail/visitor.h>
#include <hilti/ast/module.h>
#include <hilti/compiler/detail/visitors.h>

using namespace hilti;

void Module::clear() {
    auto v = visitor::PostOrder<>();

    // We fully walk the AST here in order to break any reference cycles it may
    // contain. Start at child 1 to leave ID in place.
    for ( size_t i = 1; i < childs().size(); i++ ) {
        for ( auto j : v.walk(&childs()[i]) )
            j.node = node::none;
    }

    childs()[1] = statement::Block({}, meta());
}

NodeRef Module::preserve(Node n) {
    detail::clearErrors(&n);
    _preserved.push_back(std::move(n));
    return NodeRef(_preserved.back());
}

Result<declaration::Property> Module::moduleProperty(const ID& id) const {
    for ( const auto& d : declarations() ) {
        if ( auto p = d.tryAs<declaration::Property>(); p && p->id() == id )
            return *p;
    }

    return result::Error("no property of specified id");
}

std::vector<declaration::Property> Module::moduleProperties(const ID& id) const {
    std::vector<declaration::Property> props;

    for ( const auto& d : declarations() ) {
        if ( auto p = d.tryAs<declaration::Property>(); p && p->id() == id )
            props.push_back(*p);
    }

    return props;
}

void Module::removeDeclaration(const ID& id) {
    auto& children = childs();

    children.erase(std::remove_if(children.begin() + 2, children.end(),
                                  [&id](const Node& child) {
                                      const auto& decl = child.tryAs<Declaration>();
                                      return decl && decl->id() == id;
                                  }),
                   children.end());

    clearCache();
}
