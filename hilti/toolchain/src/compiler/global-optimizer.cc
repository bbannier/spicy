// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#include "hilti/compiler/global-optimizer.h"

#include <optional>
#include <tuple>
#include <unordered_set>
#include <utility>

#include <hilti/ast/ctors/default.h>
#include <hilti/ast/declarations/function.h>
#include <hilti/ast/detail/visitor.h>
#include <hilti/ast/expressions/ctor.h>
#include <hilti/ast/node.h>
#include <hilti/ast/statements/block.h>
#include <hilti/ast/types/struct.h>
#include <hilti/base/logger.h>
#include <hilti/base/timing.h>
#include <hilti/base/util.h>

namespace hilti {

using ModuleID = GlobalOptimizer::ModuleID;
using StructID = GlobalOptimizer::StructID;
using FieldID = GlobalOptimizer::FieldID;

namespace logging::debug {
inline const DebugStream GlobalOptimizer("global-optimizer");
} // namespace logging::debug

enum class Stage { COLLECT, PRUNE };

template<typename T>
std::optional<std::pair<ModuleID, StructID>> typeID(T&& x) {
    auto id = x.typeID();
    if ( ! id )
        return {};

    return {{id->sub(-2), id->sub(-1)}};
}

std::pair<StructID, FieldID> declID(const ID& id) { return {id.sub(-2), id.sub(-1)}; }

// Helper function to determine whether a hook should be stored.
bool goodHook(const std::tuple<ModuleID, StructID, FieldID>& hook) {
    // To collect both declaration of member functions and free
    // functions we allow `struct_id` to be empty; all other
    // identifiers are required so we can distinguish different
    // functions.
    return ! std::get<0>(hook).empty() && ! std::get<2>(hook).empty();
}

struct Visitor : hilti::visitor::PreOrder<bool, Visitor> {
    Visitor(GlobalOptimizer::Hooks* hooks) : _hooks(hooks) {}

    template<typename T>
    static void replaceNode(const position_t& p, T&& n) {
        p.node = std::forward<T>(n);
    }

    static void removeNode(position_t& p) { replaceNode(p, node::none); }

    Stage _stage = Stage::COLLECT;
    GlobalOptimizer::Hooks* _hooks = nullptr;

    void collect(Node& node) {
        _stage = Stage::COLLECT;

        for ( auto i : this->walk(&node) )
            dispatch(i);
    }

    void prune(Node& node) {
        _stage = Stage::PRUNE;

        for ( auto&& [hook_id, uses] : *_hooks ) {
            std::cerr << "NOPE: " << std::get<0>(hook_id) << ' ' << std::get<1>(hook_id) << ' ' << std::get<2>(hook_id)
                      << '\n';
            // Linker joins are implemented via functions, so if we remove all
            // functions data dependencies (e.g., needed for subunits) might
            // get broken. Leave at least one function in unit so it gets emitted.
            //
            // TODO(bbannier): Explicitly express data dependencies in joins,
            // see https://github.com/zeek/spicy/issues/918.
            if ( std::get<2>(hook_id) == std::string("__str__") ) {
                uses.defined = true;
                continue;
            }
        }

        while ( true ) {
            bool modified = false;
            for ( auto i : this->walk(&node) ) {
                if ( auto x = dispatch(i) )
                    modified = modified || *x;
            }

            if ( ! modified )
                break;
        }
    }

    result_t operator()(const type::struct_::Field& x, position_t p) {
        if ( auto type_ = x.type().tryAs<type::Function>(); ! type_ )
            return false;

        auto field_id = x.id();

        auto struct_type = typeID(p.parent().as<type::Struct>());
        if ( ! struct_type )
            return false;

        auto&& [module_id, struct_id] = *struct_type;

        auto type_ = p.findParent<declaration::Type>();
        bool is_cxx = type_ && AttributeSet::find(type_->get().attributes(), "&cxxname");

        auto hook_id = std::make_tuple(module_id, struct_id, field_id);

        if ( ! goodHook(hook_id) )
            return false;

        switch ( _stage ) {
            case Stage::COLLECT: {
                auto& hook = (*_hooks)[hook_id];

                auto fn = x.childsOfType<Function>();
                assert(fn.size() <= 1);

                bool is_always_emit = ! fn.empty() && AttributeSet::find(fn.front().attributes(), "&always-emit");

                // Record a declaration for this member.
                hook.declared = true;

                // If the member declaration is marked `&always-emit` mark it as implemented.
                if ( is_always_emit )
                    hook.defined = true;

                // If the member declaration includes a body mark it as implemented.
                if ( ! fn.empty() && fn.front().body() )
                    hook.defined = true;

                // If the unit is wrapped in a type with a `&cxxname`
                // attribute its members are defined in C++ as well.
                if ( is_cxx )
                    hook.defined = true;

                break;
            }

            case Stage::PRUNE: {
                const auto& hook = _hooks->at(hook_id);

                // Remove hooks without implementation.
                if ( ! hook.defined ) {
                    HILTI_DEBUG(logging::debug::GlobalOptimizer,
                                util::fmt("removing field for unused hook %s::%s::%s", module_id, struct_id, field_id));
                    removeNode(p);

                    return true;
                }

                break;
            }
        }

        return false;
    }

    result_t operator()(const declaration::Function& x, position_t p) {
        auto module_id = x.id().sub(-3);
        if ( module_id.empty() ) {
            // HILTI hook functions do not include the name their module in their ID.
            if ( auto module = p.findParent<Module>() )
                module_id = module->get().id();
        }

        auto struct_id = x.id().sub(-2);
        auto field_id = x.id().sub(-1);

        auto hook_id = std::make_tuple(module_id, struct_id, field_id);

        if ( ! goodHook(hook_id) )
            return false;

        switch ( _stage ) {
            case Stage::COLLECT: {
                // Record this hook as declared if it is not already known.
                auto& hook = (*_hooks)[hook_id];
                hook.declared = true;

                // If the declaration contains a body mark the function as defined.
                if ( ! x.childsOfType<statement::Block>().empty() )
                    hook.defined = true;

                break;
            }

            case Stage::PRUNE:
                const auto& hook = _hooks->at(hook_id);

                auto module = p.findParent<Module>();

                if ( ! module ) {
                    const auto& root = p.parent(p.pathLength() - 1);
                    for ( auto&& child : root.childs() ) {
                        if ( auto module_ = child.tryAs<Module>() ) {
                            module = module_;
                            break;
                        }
                    }
                }

                assert(module);

                // Defer ourself until the declaration is removed.
                //
                // FIXME(bbannier):: This should become unnecessary once we remove uses of `NodeRef`.
                for ( auto&& decl : module->get().declarations() ) {
                    if ( module_id == module->get().id() && field_id == decl.id() )
                        return true;
                }


                if ( ! hook.defined ) {
                    if ( ! struct_id.empty() ) {
                        HILTI_DEBUG(logging::debug::GlobalOptimizer,
                                    util::fmt("removing function declaration for unused hook %s::%s::%s", module_id,
                                              struct_id, field_id));
                    }
                    else {
                        HILTI_DEBUG(logging::debug::GlobalOptimizer,
                                    util::fmt("removing function declaration for unused hook %s::%s", module_id,
                                              field_id));
                    }

                    removeNode(p);
                    return true;
                }

                break;
        }

        return false;
    }

    result_t operator()(const operator_::struct_::MemberCall& x, position_t p) {
        if ( ! x.hasOp1() )
            return false;

        assert(x.hasOp0());

        auto struct_type = typeID(x.op0().type());
        if ( ! struct_type )
            return false;

        auto&& [module_id, struct_id] = *struct_type;

        auto&& member = x.op1().tryAs<expression::Member>();
        if ( ! member )
            return false;

        auto hook_id = std::make_tuple(module_id, struct_id, member->id());

        if ( ! goodHook(hook_id) )
            return false;

        switch ( _stage ) {
            case Stage::COLLECT: {
                auto& hook = (*_hooks)[hook_id];

                hook.referenced = true;
                return false;
            }

            case Stage::PRUNE: {
                const auto& hook = _hooks->at(hook_id);

                // Replace call node referencing unimplemented hook with default value.
                if ( ! hook.defined ) {
                    if ( auto fn = member->memberType()->tryAs<type::Function>() ) {
                        HILTI_DEBUG(logging::debug::GlobalOptimizer,
                                    util::fmt("replacing call to unimplemented hook %s::%s::%s with default value",
                                              module_id, struct_id, member->id()));

                        p.node = Expression(expression::Ctor(ctor::Default(fn->result().type())));

                        return true;
                    }
                }

                break;
            }
        }

        return false;
    }

    result_t operator()(const operator_::function::Call& call, position_t p) {
        if ( ! call.hasOp0() )
            return false;

        auto id = call.op0().tryAs<expression::ResolvedID>();

        if ( ! id )
            return false;

        auto [module_id, fn_id] = declID(id->id());

        if ( module_id.empty() ) {
            // Functions declared in this module do not include a module name in their ID.
            if ( auto module = p.findParent<Module>() )
                module_id = module->get().id();
        }

        auto hook_id = std::make_tuple(module_id, "", fn_id);

        if ( ! goodHook(hook_id) )
            return false;


        switch ( _stage ) {
            case Stage::COLLECT: {
                auto& hook = (*_hooks)[hook_id];

                hook.referenced = true;
                return false;
            }

            case Stage::PRUNE: {
                const auto& hook = _hooks->at(hook_id);

                // Replace call node referencing unimplemented hook with default value.
                if ( ! hook.defined ) {
                    // FIXME(bbannier): this can run after the declaration is removeed at which point the result type
                    // becomes inaccessible. This should go away once `NodeRef` got phased out.
                    if ( auto fn = id->declaration().tryAs<declaration::Function>() ) {
                        HILTI_DEBUG(logging::debug::GlobalOptimizer,
                                    util::fmt("replacing call to unimplemented hook %s::%s with default value",
                                              module_id, fn_id));

                        p.node = Expression(expression::Ctor(ctor::Default(fn->function().type().result().type())));

                        return true;
                    }
                }

                break;
            }
        }

        return false;
    }

    result_t operator()(const Module& module, position_t p) {
        switch ( _stage ) {
            case Stage::COLLECT:
                // Nothing.
                break;
            case Stage::PRUNE: {
                auto new_module = module;

                bool modified = false;

                for ( const auto& decl : module.declarations() ) {
                    if ( decl.isA<declaration::Function>() ) {
                        const auto& [struct_id, fn_id] = declID(decl.id());

                        auto hook_id = std::make_tuple(module.id(), struct_id, fn_id);

                        if ( ! goodHook(hook_id) )
                            continue;

                        if ( const auto& hook = _hooks->at(hook_id); ! hook.defined ) {
                            new_module.removeDeclaration(decl.id());
                            modified = true;
                        }
                    }
                }

                if ( modified )
                    replaceNode(p, std::move(new_module));

                return modified;
            }
        }

        return false;
    }
};

void GlobalOptimizer::run() {
    util::timing::Collector _("hilti/compiler/global-optimizer");

    // Create a full list of units to run on. This includes both the units
    // explicitly passed on construction as well as their dependencies.
    auto units = [&]() {
        // We initially store the list as a `set` to ensure uniqueness, but
        // convert to a `vector` so we can mutate entries while iterating.
        auto NodeRefCmp = [](const NodeRef& lhs, const NodeRef& rhs) { return lhs->identity() < rhs->identity(); };
        std::set<NodeRef, decltype(NodeRefCmp)> units(NodeRefCmp);

        for ( auto& unit : *_units ) {
            units.insert(NodeRef(unit.imported(unit.id())));

            for ( auto&& dep : _ctx->lookupDependenciesForModule(unit.id()) )
                units.insert(NodeRef(unit.imported(dep.index.id)));
        }

        return std::vector<NodeRef>{units.begin(), units.end()};
    }();

    for ( auto& unit : units )
        Visitor(&_hooks).collect(*unit);

    for ( auto& unit : units )
        Visitor(&_hooks).prune(*unit);
}

} // namespace hilti