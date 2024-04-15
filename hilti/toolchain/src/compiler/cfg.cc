// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include "hilti/compiler/detail/cfg.h"

#include <algorithm>
#include <iterator>
#include <optional>
#include <utility>

#include <hilti/ast/declaration.h>
#include <hilti/ast/declarations/local-variable.h>
#include <hilti/ast/expressions/assign.h>
#include <hilti/ast/expressions/name.h>
#include <hilti/ast/node.h>
#include <hilti/ast/statement.h>
#include <hilti/ast/statements/block.h>
#include <hilti/ast/statements/declaration.h>
#include <hilti/ast/statements/expression.h>
#include <hilti/ast/statements/if.h>
#include <hilti/ast/statements/return.h>
#include <hilti/ast/statements/throw.h>
#include <hilti/ast/statements/try.h>
#include <hilti/ast/statements/while.h>
#include <hilti/ast/type.h>
#include <hilti/ast/visitor.h>
#include <hilti/base/util.h>

namespace hilti {
std::istream& operator>>(std::istream&, Node*) { util::cannotBeReached(); }

std::string node_id(const Node* n) { return util::fmt("%d", n ? n->identity() : 0); }

namespace detail::cfg {

uint64_t MetaNode::instances = 0;

// Ad-hoc sorting for nodes.
//
// FIXME(bbannier): We only need this as we have no way to access graph nodes
// in a deterministic order below. Drop this should we switch to a graph
// library which provides that.
bool operator<(const Node& a, const Node& b) {
    auto* metaA = a.tryAs<MetaNode>();
    auto* metaB = b.tryAs<MetaNode>();

    // Distinguish MetaNodes by counter.
    if ( metaA && metaB ) {
        if ( metaA != metaB )
            assert(metaA->counter != metaB->counter);
        return metaA->counter < metaB->counter;
    }

    // MetaNodes sort before other Nodes.
    else if ( metaA && ! metaB ) {
        return true;
    }
    else if ( ! metaA && metaB ) {
        return false;
    }

    // Other nodes are distinguished by content hash.
    else {
        auto hasher = std::hash<std::string>();
        return hasher(a.print()) < hasher(b.print());
    }
}

CFG::CFG(const N& root)
    : begin(get_or_add_node(create_meta_node<Start>())), end(get_or_add_node(create_meta_node<End>())) {
    assert(root && root->isA<statement::Block>() && "only building from blocks currently supported");

    auto last = add_block(begin, root->children());
    add_edge(last, end);
}

CFG::NodeP CFG::add_block(NodeP parent, const Nodes& stmts) {
    // If `children` directly has any statements which change control flow like
    // `throw` or `return` any statements after that are unreachable. To model
    // such ASTs we add a flow with all statements up to the "last" semantic
    // statement (either the last child or the control flow statement) to the
    // CFG under `parent`. Statements after that are added as children without
    // parents, and mixed with the previous flow.

    // After this block `last` is the last reachable statement, either end of
    // children or a control flow statement.
    auto last = std::find_if(stmts.begin(), stmts.end(), [](auto&& c) {
        return c && (c->template isA<statement::Return>() || c->template isA<statement::Throw>());
    });
    const bool has_dead_flow = last != stmts.end();
    if ( has_dead_flow )
        last = std::next(last);

    // Add all statements which are part of the normal flow.
    for ( auto&& c : (last != stmts.end() ? Nodes(stmts.begin(), last) : stmts) ) {
        if ( ! c || ! c->isA<Statement>() )
            continue;

        if ( auto&& while_ = c->tryAs<statement::While>() )
            parent = add_while(parent, *while_);

        else if ( auto&& if_ = c->tryAs<statement::If>() )
            parent = add_if(parent, *if_);

        else if ( auto&& try_catch = c->tryAs<statement::Try>() )
            parent = add_try_catch(parent, *try_catch);

        else if ( auto&& return_ = c->tryAs<statement::Return>() )
            parent = add_return(parent, return_->expression());

        else if ( auto&& throw_ = c->tryAs<statement::Throw>() )
            parent = add_return(parent, throw_->expression());

        else {
            auto cc = get_or_add_node(c);

            add_edge(parent, cc);
            add_block(parent, c->children());

            // Update `last` so sibling nodes get chained.
            parent = std::move(cc);
        }
    }

    // Add unreachable flows.
    if ( has_dead_flow && last != stmts.end() ) {
        auto next = add_block(nullptr, Nodes{last, stmts.end()});
        auto mix = get_or_add_node(create_meta_node<Flow>());
        add_edge(parent, mix);
        add_edge(next, mix);
        parent = std::move(mix);
    }

    return parent;
}

CFG::NodeP CFG::add_while(NodeP parent, const statement::While& while_) {
    auto&& condition = get_or_add_node(while_.condition());
    add_edge(std::move(parent), condition);

    auto body_end = add_block(condition, while_.body()->children());
    add_edge(body_end, condition);
    if ( auto&& else_ = while_.else_() ) {
        auto&& else_end = add_block(condition, else_->children());

        auto mix = get_or_add_node(create_meta_node<Flow>());

        add_edge(else_end, mix);
        add_edge(condition, mix);

        return mix;
    }

    return condition;
}

CFG::NodeP CFG::add_if(NodeP parent, const statement::If& if_) {
    auto&& condition = get_or_add_node(if_.condition());
    add_edge(std::move(parent), condition);

    auto true_end = add_block(condition, if_.true_()->children());
    if ( auto false_ = if_.false_() ) {
        auto false_end = add_block(condition, false_->children());
        auto mix = get_or_add_node(create_meta_node<Flow>());

        add_edge(false_end, mix);
        add_edge(true_end, mix);

        return mix;
    }

    return true_end;
}

CFG::NodeP CFG::add_try_catch(const NodeP& parent, const statement::Try& try_catch) {
    auto try_ = add_block(parent, try_catch.body()->children());
    auto mix = get_or_add_node(create_meta_node<Flow>());
    add_edge(try_, mix);

    for ( auto&& catch_ : try_catch.catches() ) {
        auto catch_end = add_block(parent, catch_->body()->children());
        add_edge(catch_end, mix);
    }

    return mix;
}

CFG::NodeP CFG::add_return(const NodeP& parent, const N& expression) {
    if ( expression ) {
        // We store the return statement to make us of it in data flow analysis.
        auto r = get_or_add_node(expression->parent());
        add_edge(parent, r);
        return r;
    }

    return parent;
}

std::shared_ptr<const CXXGraph::Node<CFG::N>> CFG::get_or_add_node(const N& n) {
    const auto& id = node_id(n);
    if ( auto x = g.getNode(id) )
        return *x;

    auto y = std::make_shared<CXXGraph::Node<N>>(id, n);
    g.addNode(y);
    return y;
}

void CFG::add_edge(NodeP from, NodeP to) {
    if ( ! from || ! to )
        return;

    if ( const auto& xs = g.outEdges(from);
         xs.end() != std::find_if(xs.begin(), xs.end(), [&](const auto& e) { return e->getNodePair().second == to; }) )
        return;
    else {
        auto e =
            std::make_shared<CXXGraph::DirectedEdge<CFG::N>>(g.getEdgeSet().size(), std::move(from), std::move(to));
        g.addEdge(std::move(e));
        return;
    }
}

std::string CFG::dot() const {
    std::stringstream ss;

    ss << "digraph {\n";

    std::unordered_map<CXXGraph::id_t, size_t> node_ids; // Deterministic node ids.

    const auto& nodes = g.getNodeSet();
    auto sorted_nodes = std::vector(nodes.begin(), nodes.end());
    std::sort(sorted_nodes.begin(), sorted_nodes.end(),
              [](const auto& a, const auto& b) { return *a->getData() < *b->getData(); });

    for ( auto&& n : sorted_nodes ) {
        auto id = node_ids.size();
        node_ids.insert({n->getId(), id});

        auto&& data = n->getData();

        std::optional<std::string> xlabel;
        if ( auto it = dataflow.find(n.get()); it != dataflow.end() ) {
            const auto& transfer = it->second;

            auto use = [&]() {
                auto xs = util::transformToVector(transfer.use, [](auto* decl) {
                    return rt::escapeUTF8(decl->template as<const hilti::Declaration>()->id(), true);
                });
                std::sort(xs.begin(), xs.end());
                return util::join(xs, ", ");
            }();

            auto gen = [&]() {
                auto xs = util::transformToVector(transfer.gen, [](auto&& kv) {
                    auto&& [decl, node] = kv;
                    return util::fmt("%s: %s",
                                     rt::escapeUTF8(decl->template as<const hilti::Declaration>()->id(), true),
                                     rt::escapeUTF8(node->getData()->print(), true));
                });
                std::sort(xs.begin(), xs.end());
                return util::join(xs, ", ");
            }();

            auto kill = [&]() {
                auto xs = util::transformToVector(transfer.kill, [&](auto&& kv) {
                    auto&& decl = kv.first;
                    auto&& nodes = kv.second;

                    return util::fmt("%s: [%s]",
                                     rt::escapeUTF8(decl->template as<const hilti::Declaration>()->id(), true),
                                     util::join(
                                         [&]() {
                                             auto xs = util::transformToVector(nodes, [](auto&& x) {
                                                 return rt::escapeUTF8(x->getData()->print(), true);
                                             });

                                             std::sort(xs.begin(), xs.end());
                                             return xs;
                                         }(),

                                         ", "));
                });
                std::sort(xs.begin(), xs.end());
                return util::join(xs, " ");
            }();

            auto reach = [&]() -> std::string {
                const auto* nn = n->getData();
                if ( ! reachable.count(nn) )
                    return {};

                const auto& r = reachable.at(nn);
                auto xs = util::transformToVector(r, [](auto&& x) { return x->getData()->print(); });

                std::sort(xs.begin(), xs.end());
                return util::join(xs, ", ");
            }();

            xlabel = util::fmt("xlabel=\"use: [%s] gen: [%s] kill: [%s] reachable: [%s]\"", use, gen, kill, reach);
        }

        if ( auto&& meta = data->tryAs<MetaNode>() ) {
            if ( data->isA<Start>() )
                ss << util::fmt("\t%s [label=start shape=Mdiamond %s];\n", id, xlabel ? *xlabel : "");

            else if ( data->isA<End>() )
                ss << util::fmt("\t%s [label=end shape=Msquare %s];\n", id, xlabel ? *xlabel : "");

            else if ( data->isA<Flow>() )
                ss << util::fmt("\t%s [shape=point %s];\n", id, xlabel ? *xlabel : "");

            else
                util::cannotBeReached();
        }

        else {
            ss << util::fmt("\t%s [label=\"%s\" %s];\n", id, rt::escapeUTF8(data->print(), true),
                            xlabel ? *xlabel : "");
        }
    }

    const auto& edges = g.getEdgeSet();
    auto sorted_edges = std::vector(edges.begin(), edges.end());
    std::sort(sorted_edges.begin(), sorted_edges.end(), [](const auto& a, const auto& b) {
        // Edges have deterministic IDs derived from the insertion order.
        return a->getId() < b->getId();
    });

    for ( auto&& e : sorted_edges ) {
        auto&& [from, to] = e->getNodePair();
        ss << util::fmt("\t%s -> %s [label=\"%s\"];\n", node_ids.at(from->getId()), node_ids.at(to->getId()),
                        e->getId());
    }

    ss << "}";

    return ss.str();
}

// We cannot use `inEdges` since it is completely broken for directed graphs,
// https://github.com/ZigRazor/CXXGraph/issues/406.
CXXGraph::T_EdgeSet<CFG::N> inEdges(const CXXGraph::Graph<CFG::N>& g, const CFG::NodeP& n) {
    CXXGraph::T_EdgeSet<CFG::N> in;

    for ( auto&& e : g.getEdgeSet() ) {
        auto&& [_, to] = e->getNodePair();

        if ( to == n )
            in.insert(e);
    }

    return in;
}

CXXGraph::T_NodeSet<CFG::N> CFG::unreachable_nodes() const {
    auto xs = nodes();

    CXXGraph::T_NodeSet<N> result;
    for ( auto&& n : xs ) {
        auto&& data = n->getData();
        if ( data && ! data->isA<MetaNode>() && inEdges(g, n).empty() )
            result.insert(n);
    }

    return result;
}

struct DataflowVisitor : visitor::PreOrder {
    DataflowVisitor(const CXXGraph::Node<CFG::N>* root_) : root(root_) {}

    const CXXGraph::Node<CFG::N>* root = nullptr;
    Transfer transfer;

    void getTransfer(const Node& x, const Declaration& decl, Transfer& transfer) const {
        auto* parent = x.parent();

        if ( ! parent )
            return;

        if ( auto* assign = parent->tryAs<expression::Assign>() ) {
            if ( assign->source() == &x )
                transfer.use.insert(&decl);

            if ( assign->target() == &x )
                transfer.gen[&decl] = root;
        }

        else if ( auto* declaration = parent->tryAs<statement::Declaration>() )
            // Outputs declared in matcher for `statement::Declaration`.
            transfer.use.insert(&decl);

        else if ( auto* return_ = parent->tryAs<statement::Return>() )
            // Simply flows a value but does not generate or kill any.
            transfer.use.insert(&decl);

        if ( parent != root->getData() )
            getTransfer(*parent, decl, transfer);
    }

    void operator()(expression::Name* x) override {
        if ( auto* decl = x->resolvedDeclaration() )
            getTransfer(*x, *decl, transfer);
    }

    void operator()(statement::Declaration* x) override { transfer.gen[x->declaration()] = root; }
};

void CFG::populate_dataflow() {
    auto visit_node = [](const CXXGraph::Node<N>* n) -> Transfer {
        if ( auto x = n->getData()->tryAs<MetaNode>() )
            return {};

        auto v = DataflowVisitor(n);
        visitor::visit(v, n->getData());

        return std::move(v.transfer);
    };

    // Populate uses and the gen sets.
    for ( auto&& n : g.getNodeSet() ) {
        if ( n->getData() )
            dataflow[n.get()] = visit_node(n.get());
    }

    { // Populate the kill sets.
        std::unordered_map<const Node*, std::unordered_set<const CXXGraph::Node<Node*>*>> gens;
        for ( auto&& [_, transfer] : dataflow ) {
            for ( auto&& [d, n] : transfer.gen )
                gens[d].insert(n);
        }

        for ( auto&& n : g.getNodeSet() ) {
            auto& transfer = dataflow[n.get()];

            for ( auto&& [d, ns] : gens ) {
                auto x = transfer.gen.find(d);
                // Only kill gens also generated in this node.
                if ( x == transfer.gen.end() )
                    continue;

                for ( auto&& nn : ns ) {
                    // Do not kill the gen in this node.
                    if ( x->second != nn )
                        transfer.kill[d].insert(nn);
                }
            }
        }
    }
}

void CFG::populate_reachable_expressions() {
    if ( dataflow.empty() )
        populate_dataflow();

    while ( true ) {
        bool changed = false;

        for ( const auto& n : g.getNodeSet() ) {
            changed |= ! reachable.count(n->getData());
            auto& r = reachable[n->getData()]; // Create new entry if non exists.

            for ( const auto& e : inEdges(g, n) ) {
                const auto& [from, _] = e->getNodePair();

                const auto& transfer = dataflow.at(from.get());

                auto num_entries0 = r.size();

                // Everything reachable by incoming nodes is reachable.
                {
                    changed |= ! reachable.count(from->getData());
                    const auto& rr = reachable[from->getData()]; // Create new entry if non exists.
                    for ( auto&& x : rr )
                        r.insert(x);
                }

                // Everything generated by incoming nodes is reachable.
                for ( const auto& [_, node] : transfer.gen )
                    r.insert(node);

                // Everything killed by incoming nodes is unreachable.
                for ( const auto& [_, nodes] : transfer.kill ) {
                    for ( const auto& nn : nodes )
                        r.erase(nn);
                }

                changed |= num_entries0 != r.size();
            }
        }

        if ( ! changed )
            break;
    }
}

} // namespace detail::cfg

} // namespace hilti
