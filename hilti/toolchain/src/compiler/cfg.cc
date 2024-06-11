// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include "hilti/compiler/detail/cfg.h"

#include <CXXGraph/Node/Node_decl.h>

#include <algorithm>
#include <cstdint>
#include <iterator>
#include <optional>
#include <unordered_map>
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

// We cannot use `inEdges` since it is completely broken for directed graphs,
// https://github.com/ZigRazor/CXXGraph/issues/406.
CXXGraph::T_EdgeSet<CFG::N> inEdges(const CXXGraph::Graph<CFG::N>& g, const CXXGraph::Node<CFG::N>* n) {
    CXXGraph::T_EdgeSet<CFG::N> in;

    for ( auto&& e : g.getEdgeSet() ) {
        auto&& [_, to] = e->getNodePair();

        if ( to.get() == n )
            in.insert(e);
    }

    return in;
}

// We cannot use `outEdges` since it is completely broken for directed graphs,
// https://github.com/ZigRazor/CXXGraph/issues/406.
CXXGraph::T_EdgeSet<CFG::N> outEdges(const CXXGraph::Graph<CFG::N>& g, const CXXGraph::Node<CFG::N>* n) {
    CXXGraph::T_EdgeSet<CFG::N> out;

    for ( auto&& e : g.getEdgeSet() ) {
        auto&& [from, _] = e->getNodePair();

        if ( from.get() == n )
            out.insert(e);
    }

    return out;
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

    if ( const auto& xs = outEdges(g, from.get());
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
                return util::fmt("use: [%s]", util::join(xs, ", "));
            }();

            auto gen = [&]() {
                auto xs = util::transformToVector(transfer.gen, [](auto&& kv) {
                    auto&& [decl, node] = kv;
                    return util::fmt("%s: %s",
                                     rt::escapeUTF8(decl->template as<const hilti::Declaration>()->id(), true),
                                     rt::escapeUTF8(node->getData()->print(), true));
                });
                std::sort(xs.begin(), xs.end());
                return util::fmt("gen: [%s]", util::join(xs, ", "));
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
                return util::fmt("kill: [%s]", util::join(xs, " "));
            }();

            auto reachability = [&]() -> std::string {
                auto&& r = transfer.reachability;
                if ( ! r )
                    return "";

                auto to_str = [](auto&& xs) {
                    auto ys = util::transformToVector(xs, [](auto&& x) {
                        return rt::escapeUTF8(x->getData()->print(), true);
                    });
                    std::sort(ys.begin(), ys.end());
                    return util::join(ys, ", ");
                };

                return util::fmt("reach: { in: [%s] out: [%s] }", to_str(r->in), to_str(r->out));
            }();

            xlabel = util::fmt("xlabel=\"%s\"", util::join({use, gen, kill, reachability}, " "));
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

CXXGraph::T_NodeSet<CFG::N> CFG::unreachable_nodes() const {
    auto xs = nodes();

    CXXGraph::T_NodeSet<N> result;
    for ( auto&& n : xs ) {
        auto&& data = n->getData();
        if ( data && ! data->isA<MetaNode>() && inEdges(g, n.get()).empty() )
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

        // FIXME(bbannier): record uses in other statements.
        // else {
        //     std::cerr << "NOPE use " << x.parent()->print() << ' ' << (x.parent() == root->getData()) << '\n';
        //     transfer.use.insert(&decl);
        // }

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

    auto nodes = g.getNodeSet();

    // Reset reachability information.
    for ( auto&& n : nodes ) {
        dataflow.at(n.get()).reachability = Reachability();
    }

    // Compute in and out sets for each node.
    while ( true ) {
        bool changed = false;

        for ( const auto& n : nodes ) {
            auto& reachability = dataflow[n.get()].reachability;
            auto& in = reachability->in;
            auto& out = reachability->out;

            // The in set is the union of all incoming nodes.
            for ( const auto& e : inEdges(g, n.get()) ) {
                const auto& [from, _] = e->getNodePair();

                const auto& from_ = dataflow.at(from.get()).reachability->out; // Must already exist.
                std::copy(from_.begin(), from_.end(), std::inserter(in, in.begin()));
                for ( auto&& f : from_ ) {
                    auto [_, inserted] = in.insert(f);
                    changed |= inserted;
                }
            }

            // The out set of a node is gen + (in - kill)
            const auto& gen = dataflow.at(n.get()).gen;
            const auto& kill = dataflow.at(n.get()).kill;

            for ( auto&& [decl, g] : gen ) {
                auto [_, inserted] = out.insert(g);
                changed |= inserted;
            }

            for ( auto&& i : in ) {
                if ( std::any_of(kill.begin(), kill.end(), [&](auto&& kv) {
                         auto&& [_, n] = kv;
                         return n.count(i);
                     }) )
                    continue;

                auto [_, inserted] = out.insert(i);
                changed |= inserted;
            }
        }

        if ( ! changed )
            break;
    }
}

std::vector<const CXXGraph::Node<CFG::N>*> CFG::unreachable_statements() const {
    // This can only be called after reachability information has been populated.
    assert(! dataflow.empty());
    assert(dataflow.begin()->second.reachability);

    std::unordered_map<const CXXGraph::Node<N>*, uint64_t> uses;

    for ( auto& [node, transfer] : dataflow ) {
        for ( auto&& o : transfer.reachability->out )
            uses[o]; // Insert if not present.

        for ( auto&& u : transfer.use ) {
            // FIXME(bbannier): uses has decls, but we do not seem to find them here so we miss uses.
            if ( auto it =
                     std::find_if(uses.begin(), uses.end(), [&](const auto& n) { return n.first->getData() == u; });
                 it != uses.end() )
                ++it->second;
        }
    }
    std::vector<const CXXGraph::Node<CFG::N>*> result;
    for ( auto&& [n, uses] : uses ) {
        if ( uses == 0 )
            result.push_back(n);
    }

    return result;
}

} // namespace detail::cfg

} // namespace hilti
