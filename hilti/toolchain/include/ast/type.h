// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include <hilti/rt/../../../3rdparty/polymorphic_value/polymorphic_value.h>
// FIXME(bbannier): can 3rdparty/any be removed?

#include <memory>
#include <string>
#include <type_traits>
#include <unordered_set>
#include <utility>
#include <vector>

#include <hilti/ast/id.h>
#include <hilti/ast/node.h>
#include <hilti/base/type_erase.h>
#include <hilti/base/util.h>
#include <hilti/base/visitor-types.h>

namespace hilti {

namespace trait {
/** Trait for classes implementing the `Type` interface. */
class isType : public isNode {};
} // namespace trait

class TypeBase;
class Type;

namespace declaration {
class Parameter;
}

namespace type {
class Address;

struct VisitorBase {
    using position_t = visitor::Position<Node>;
    virtual void operator()(const Type&, position_t&) {}
};

namespace function {
using Parameter = declaration::Parameter;
}

namespace trait {
struct Traits {
    bool isAllocable = false;
    bool isDereferenceable = false;
    bool isIterable = false;
    bool isIterator = false;
    bool isMutable = false;
    bool isParameterized = false;
    bool isReferenceType = false;
    bool isRuntimeNonTrivial = false;
    bool isView = false;
    bool isViewable = false;
    bool takesArguments = false;
};

struct isAllocable {
    isAllocable(Traits* all) { all->isAllocable = true; }
};

struct isDereferenceable {
    isDereferenceable(Traits* all) { all->isDereferenceable = true; }

    /** Returns the type of elements the iterator traverse. */
    virtual const hilti::Type& dereferencedType() const = 0;
};

struct isIterable {
    isIterable(Traits* all) { all->isIterable = true; }

    /** Returns the type of an iterator for this type. */
    virtual const hilti::Type& iteratorType(bool const_) const = 0;

    /** Returns the type of elements the container stores. */
    virtual const hilti::Type& elementType() const = 0;
};

struct isIterator {
    isIterator(Traits* all) { all->isIterator = true; }
};

struct isMutable {
    isMutable(Traits* all) { all->isMutable = true; }
};

struct isParameterized {
    isParameterized(Traits* all) { all->isParameterized = true; }

    /**
     * Returns true if all instances of the same type class can be coerced
     * into the current instance, independent of their pararameters. In HILTI
     * source code, this typically corresponds to a type `T<*>`.
     */
    virtual bool isWildcard() const = 0;

    /**
     * Returns any parameters associated with type. If a type is declared as
     * `T<A,B,C>` this returns a vector of the AST nodes for `A`, `B`, and
     * `C`.
     */
    virtual std::vector<Node> typeParameters() const = 0;
};

struct isReferenceType {
    isReferenceType(Traits* all) { all->isReferenceType = true; }
};

struct isRuntimeNonTrivial {
    isRuntimeNonTrivial(Traits* all) { all->isRuntimeNonTrivial = true; }
};

struct isView : isIterable {
    isView(Traits* all) : isIterable(all) { all->isView = true; }
};

struct isViewable {
    isViewable(Traits* all) { all->isViewable = true; }

    /**
     * Returns any parameters associated with type. If a type is declared as
     * `T<A,B,C>` this returns a vector of the AST nodes for `A`, `B`, and
     * `C`.
     */
    /** Returns the type of an view for this type. */
    virtual const hilti::Type& viewType() const = 0;
};

class supportsWildcard {};

struct takesArguments {
    takesArguments(Traits* all) { all->takesArguments = true; }

    /** Returns any parameters the type expects. */
    virtual hilti::node::Set<type::function::Parameter> parameters() const = 0;
};

} // namespace trait

using ResolvedState = std::unordered_set<uintptr_t>;

/** Additional flags to associated with types. */
enum class Flag {
    /** Set to make the type `const`. */
    Constant = (1U << 0U),

    /** Set to make the type `non-const`. */
    NonConstant = (1U << 1U),

    /**
     * Marks the type as having a top-level scope that does not derive scope content
     * from other nodes above it in the AST (except for truly global IDs).
     */
    NoInheritScope = (1U << 2U),

    /** When walking over an AST, skip this node's children. This allows to
     * break cycles. */
    PruneWalk = (1U << 3U),
};

/**
 * Stores a set of flags associated with a type.
 *
 * TODO: Replace with 3rd-party/ArticleEnumClass-v2/EnumClass.h
 */
class Flags {
public:
    Flags() = default;
    Flags(Flag f) : _flags(static_cast<uint64_t>(f)) {}
    Flags(const Flags&) = default;
    Flags(Flags&&) noexcept = default;
    ~Flags() = default;

    /** Returns true if a given flag has been set. */
    bool has(Flag f) const { return _flags & static_cast<uint64_t>(f); }

    /** Sets (or clear) a given flag. */
    void set(type::Flag flag, bool set = true) {
        if ( set )
            _flags |= static_cast<uint64_t>(flag);
        else
            _flags &= ~static_cast<uint64_t>(flag);
    }

    Flags operator+(Flag f) {
        auto x = Flags(*this);
        x.set(f);
        return x;
    }

    Flags operator+(const Flags& other) const {
        auto x = Flags();
        x._flags = _flags | other._flags;
        return x;
    }

    Flags& operator+=(Flag f) {
        set(f);
        return *this;
    }
    Flags& operator+=(const Flags& other) {
        _flags |= other._flags;
        return *this;
    }

    Flags operator-(const Flags& other) const {
        auto x = Flags();
        x._flags = _flags & ~other._flags;
        return x;
    }

    Flags& operator-=(Flag f) {
        set(f, false);
        return *this;
    }
    Flags& operator-=(const Flags& other) {
        _flags &= ~other._flags;
        return *this;
    }

    Flags& operator=(Flag f) {
        set(f);
        return *this;
    }
    Flags& operator=(const Flags&) = default;
    Flags& operator=(Flags&&) noexcept = default;

    bool operator==(Flags other) const { return _flags == other._flags; }

    bool operator!=(Flags other) const { return _flags != other._flags; }

private:
    uint64_t _flags = 0;
};

inline Flags operator+(Flag f1, Flag f2) { return Flags(f1) + f2; }

namespace detail {
struct State {
    std::optional<ID> id;
    std::optional<ID> cxx;
    std::optional<ID> resolved_id;
    type::Flags flags;
};
} // namespace detail

} // namespace type


/**
 * Base class for classes implementing the `Type` interface. This class
 * provides implementations for some interface methods shared that are shared
 * by all types.
 */
class TypeBase : public NodeBase, public trait::isType {
public:
    TypeBase(const std::type_info& type_info_)
        : _typename(util::demangle(type_info_.name())), _typeid(type_info_.hash_code()) {}
    TypeBase(const std::type_info& type_info_, Meta meta)
        : NodeBase(std::move(meta)), _typename(util::demangle(type_info_.name())), _typeid(type_info_.hash_code()) {}

    TypeBase(const std::type_info& type_info_, std::vector<Node> children, Meta meta)
        : NodeBase(std::move(children), std::move(meta)),
          _typename(util::demangle(type_info_.name())),
          _typeid(type_info_.hash_code()) {}

    TypeBase(TypeBase&&) = default;
    TypeBase(const TypeBase&) = default;

    ~TypeBase() override = default;

    // Generic node stuff. {{{
    template<typename T>
    bool isA() const {
        return dynamic_cast<const T*>(this);
    }

    template<typename T>
    T& as() {
        return *dynamic_cast<T*>(this);
    }

    template<typename T>
    const T& as() const {
        return *dynamic_cast<const T*>(this);
    }

    template<typename T>
    optional_ref<const T> tryAs() const {
        if ( auto* p = dynamic_cast<const T*>(this) )
            return *p;
        return {};
    }

    template<typename T>
    optional_ref<T> tryAs() {
        if ( auto* p = dynamic_cast<T*>(this) )
            return *p;
        return {};
    }

    std::string typename_() const override { return _typename; }

    size_t typeid_() const override { return _typeid; }

    virtual uintptr_t identity() const {
        // FIXME(bbannier): is this correct?
        return reinterpret_cast<uintptr_t>(this);
    }

    /** Implements the `Node` interface. */
    virtual node::Properties properties() const { return {}; }

    /** Implements the `Node` interface. */
    std::vector<hilti::Node>& children() const {
        static std::vector<hilti::Node> _children; // FIXME(bbannier)
        return _children;
    }

    /** Implements the `Node` interface. */
    const Meta& meta() const { return _meta; }

    /** Implements the `Node` interface. */
    void setMeta(Meta m) { _meta = std::move(m); }
    Meta _meta;

    // }}}

    // Type interface. {{{
    virtual bool isEqual(const Type& other) const { return false; }
    virtual bool _isResolved(type::ResolvedState* rstate) const { return false; }
    // }}}

    const type::trait::Traits& _traits() const { return _traits_; }
    type::trait::Traits& _traits() { return _traits_; }

protected:
    type::trait::Traits _traits_;

private:
    std::string _typename; // FIXME(bbannier): can compute dynamically?
    size_t _typeid;        // FIXME(bbannier): can compute dynamically?
};

class Type : public NodeBase {
public:
    Type() = default;

    template<typename T, typename = std::enable_if_t<std::is_base_of_v<TypeBase, T>>>
    Type(T t) : _data_(isocpp_p0201::make_polymorphic_value<TypeBase>(t)) {}

    Type(const Type& t) = default;
    Type(Type&& t) = default;

    Type& operator=(const Type& t) = default;
    Type& operator=(Type&&) = default;

    // Generic node stuff. {{{
    template<typename T>
    bool isA() const {
        return _data_->isA<T>();
    }

    template<typename T>
    T& as() {
        return _data_->as<T>();
    }

    template<typename T>
    const T& as() const {
        return _data_->as<T>();
    }

    template<typename T>
    optional_ref<const T> tryAs() const {
        return _data_->tryAs<T>();
    }

    template<typename T>
    optional_ref<T> tryAs() {
        return _data_->tryAs<T>();
    }

    std::string typename_() const override { return _data_->typename_(); }
    size_t typeid_() const override { return _data_->typeid_(); }

    virtual uintptr_t identity() const {
        // FIXME(bbannier): is this correct?
        return reinterpret_cast<uintptr_t>(this);
    }

    /** Implements the `Node` interface. */
    virtual node::Properties properties() const { return {}; }

    /** Implements the `Node` interface. */
    std::vector<hilti::Node>& children() const {
        static std::vector<hilti::Node> _children; // FIXME(bbannier)
        return _children;
    }

    /** Implements the `Node` interface. */
    const Meta& meta() const { return _meta; }

    /** Implements the `Node` interface. */
    void setMeta(Meta m) { _meta = std::move(m); }
    Meta _meta;

    // }}}

    /** Returns true if the type is equivalent to another HILTI type. */
    bool isEqual(const hilti::Type& other) const { return node::isEqual(&_data(), other._data()); }

    /** For internal use. Use ``type::isResolved` instead. */
    virtual bool _isResolved(type::ResolvedState* rstate) const { return false; }

    Type _clone() const { return *this; }

    /** For internal use. Use ``type::isAllocable` instead. */
    bool _isAllocable() const { return _data_->_traits().isAllocable; }

    /** For internal use. Use ``type::isDereferenceable` instead. */
    bool _isDereferenceable() const { return _data_->_traits().isDereferenceable; }

    /** For internal use. Use ``type::isIterable` instead. */
    bool _isIterable() const { return _data_->_traits().isIterable; }

    /** For internal use. Use ``type::isViewable` instead. */
    bool _isViewable() const { return _data_->_traits().isViewable; }

    /** For internal use. Use ``type::isIterator` instead. */
    bool _isIterator() const { return _data_->_traits().isIterator; }

    /** For internal use. Use ``type::isView` instead. */
    bool _isView() const { return _data_->_traits().isView; }

    /** For internal use. Use ``type::isParameterized` instead. */
    bool _isParameterized() const { return _data_->_traits().isParameterized; }

    /** For internal use. Use ``type::isReferenceType` instead. */
    bool _isReferenceType() const { return _data_->_traits().isReferenceType; }

    /** For internal use. Use ``type::isMutable` instead. */
    bool _isMutable() const { return _data_->_traits().isMutable; }

    /** For internal use. Use ``type::isRuntimeNonTrivial` instead. */
    bool _isRuntimeNonTrivial() const { return _data_->_traits().isRuntimeNonTrivial; }

    /** For internal use. Use ``type::takesArguments` instead. */
    bool _takesArguments() const { return _data_->_traits().takesArguments; }

    std::optional<ID> resolvedID() const { return _state().resolved_id; }

    void setCxxID(ID id) { _state().cxx = std::move(id); }
    void setTypeID(ID id) { _state().id = std::move(id); }
    void addFlag(type::Flag f) { _state().flags += f; }

    /** Implements the `Type` interface. */
    bool hasFlag(type::Flag f) const { return _state().flags.has(f); }
    /** Implements the `Type` interface. */
    const type::Flags& flags() const { return _state().flags; }
    /** Implements the `Type` interface. */
    bool _isConstant() const { return _state().flags.has(type::Flag::Constant); }
    /** Implements the `Type` interface. */
    const std::optional<ID>& typeID() const { return _state().id; }
    /** Implements the `Type` interface. */
    const std::optional<ID>& cxxID() const { return _state().cxx; }
    /** Implements the `Type` interface. */
    const type::detail::State& _state() const { return _state_; }
    /** Implements the `Type` interface. */
    type::detail::State& _state() { return _state_; }
    /** Implements the `Node` interface. */
    bool pruneWalk() const { return hasFlag(type::Flag::PruneWalk); }

    const TypeBase& _data() const { return *_data_; }

    // FIXME(bbannier): Ideally this would be pure virtual, but then we couldn't have `Type` values anymore. Maybe
    // reconsider this if we had reference semantics.

    // FIXME(bbannier): this should be declared in the type at the base of the visitable hierarchy.
    virtual void accept(type::VisitorBase& v, type::VisitorBase::position_t& p) { v(*this, p); }

private:
    type::detail::State _state_;
    isocpp_p0201::polymorphic_value<TypeBase> _data_; // FIXME(bbannier): use this.
};

/** Creates an AST node representing a `Type`. */
inline Node to_node(Type t) { return Node(std::move(t)); }

/** Renders a type as HILTI source code. */
inline std::ostream& operator<<(std::ostream& out, const Type& t) { return out << to_node(t); }

namespace type {
namespace detail {
extern void applyPruneWalk(hilti::Type& t);
} // namespace detail

inline Type pruneWalk(Type t) {
    detail::applyPruneWalk(t);
    return t;
}

/**
 * Copies an existing type, adding additional type flags.
 *
 * @param t original type
 * @param flags additional flags
 * @return new type with the additional flags set
 */
inline hilti::Type addFlags(const Type& t, const type::Flags& flags) {
    auto x = Type(t);
    x._state().flags += flags;
    return x;
}

/**
 * Copies an existing type, removing specified type flags.
 *
 * @param t original type
 * @param flags flags to remove
 * @return new type with the flags removed
 */
inline hilti::Type removeFlags(const Type& t, const type::Flags& flags) {
    auto x = Type(t);
    x._state().flags -= flags;
    return x;
}

/**
 * Copies an existing type, setting its C++ ID as emitted by the code generator.
 *
 * @param t original type
 * @param id new C++ ID
 * @return new type with the C++ ID set accordindly
 */
inline hilti::Type setCxxID(const Type& t, ID id) {
    auto x = Type(t);
    x._state().cxx = std::move(id);
    return x;
}

/**
 * Copies an existing type, setting its associated type ID.
 *
 * @param t original type
 * @param id new type ID
 * @return new type with associateed type ID set accordindly
 */
inline hilti::Type setTypeID(const Type& t, ID id) {
    auto x = Type(t);
    x._state().id = std::move(id);
    return x;
}

/**
 * Place-holder class used to enable overloading of type constructors when
 * creating wildcard types.
 */
class Wildcard {};

/** Returns true for HILTI types that can be used to instantiate variables. */
inline bool isAllocable(const Type& t) { return t._isAllocable(); }

/** Returns true for HILTI types that one can iterator over. */
inline bool isDereferenceable(const Type& t) { return t._isDereferenceable(); }

/** Returns true for HILTI types that one can iterator over. */
inline bool isIterable(const Type& t) { return t._isIterable(); }

/** Returns true for HILTI types that represent iterators. */
inline bool isIterator(const Type& t) { return t._isIterator(); }

/** Returns true for HILTI types that are parameterized with a set of type parameters. */
inline bool isParameterized(const Type& t) { return t._isParameterized(); }

/** Returns true for HILTI types that implement a reference to another type. */
inline bool isReferenceType(const Type& t) { return t._isReferenceType(); }

/** Returns true for HILTI types that can change their value. */
inline bool isMutable(const Type& t) { return t._isMutable(); }

/** Returns true for HILTI types that, when compiled, correspond to non-POD C++ types. */
inline bool isRuntimeNonTrivial(const Type& t) { return t._isRuntimeNonTrivial(); }

/** Returns true for HILTI types that represent iterators. */
inline bool isView(const Type& t) { return t._isView(); }

/** Returns true for HILTI types that one can create a view for. */
inline bool isViewable(const Type& t) { return t._isViewable(); }

/** Returns true for HILTI types that may receive type arguments on instantiations. */
inline bool takesArguments(const Type& t) { return t._takesArguments(); }

/**
 * Returns true if the type is marked constant.
 *
 * \todo Note that currently we track this consistently only for mutable
 * types. Ideally, this would always return true for non-mutable types, but
 * doing so breaks some coercion code currently.
 */
inline bool isConstant(const Type& t) {
    return t.flags().has(type::Flag::Constant) || (! isMutable(t) && ! t.flags().has(type::Flag::NonConstant));
}

/** Returns a `const` version of a type. */
inline auto constant(Type t) {
    t._state().flags -= type::Flag::NonConstant;
    t._state().flags += type::Flag::Constant;
    return t;
}

/**
 * Returns a not `const` version of a type. If `force` is true, then even
 * immutable types are marked as non-const. This is usually not what one wants.
 */
inline auto nonConstant(Type t, bool force = false) {
    t._state().flags -= type::Flag::Constant;

    if ( force )
        t._state().flags += type::Flag::NonConstant;

    return t;
}

namespace detail {
// Internal backends for the `isResolved()`.
extern bool isResolved(const hilti::Type& t, ResolvedState* rstate);

inline bool isResolved(const std::optional<hilti::Type>& t, ResolvedState* rstate) {
    return t.has_value() ? isResolved(*t, rstate) : true;
}

inline bool isResolved(const std::optional<const hilti::Type>& t, ResolvedState* rstate) {
    return t.has_value() ? isResolved(*t, rstate) : true;
}
} // namespace detail

/** Returns true if the type has been fully resolved, including all sub-types it may include. */
extern bool isResolved(const Type& t);

/** Returns true if the type has been fully resolved, including all sub-types it may include. */
inline bool isResolved(const std::optional<Type>& t) { return t.has_value() ? isResolved(*t) : true; }

/** Returns true if the type has been fully resolved, including all sub-types it may include. */
inline bool isResolved(const std::optional<const Type>& t) { return t.has_value() ? isResolved(*t) : true; }

/** Returns true if two types are identical, ignoring for their constnesses. */
inline bool sameExceptForConstness(const Type& t1, const Type& t2) {
    if ( &t1 == &t2 )
        return true;

    if ( t1.typeID() && t2.typeID() )
        return *t1.typeID() == *t2.typeID();

    if ( t1.cxxID() && t2.cxxID() )
        return *t1.cxxID() == *t2.cxxID();

    return t1.isEqual(t2) || t2.isEqual(t1);
}

} // namespace type

inline bool operator==(const Type& t1, const Type& t2) {
    if ( &t1 == &t2 )
        return true;

    if ( type::isMutable(t1) || type::isMutable(t2) ) {
        if ( type::isConstant(t1) && ! type::isConstant(t2) )
            return false;

        if ( type::isConstant(t2) && ! type::isConstant(t1) )
            return false;
    }

    if ( t1.typeID() && t2.typeID() )
        return *t1.typeID() == *t2.typeID();

    if ( t1.cxxID() && t2.cxxID() )
        return *t1.cxxID() == *t2.cxxID();

    // Type comparison is not fully symmetric, it's good enough
    // if one type believes it matches the other one.
    return t1.isEqual(t2) || t2.isEqual(t1);
}

inline bool operator!=(const Type& t1, const Type& t2) { return ! (t1 == t2); }

/** Constructs an AST node from any class implementing the `Type` interface. */
template<typename T, typename std::enable_if_t<std::is_base_of<trait::isType, T>::value>* = nullptr>
inline Node to_node(T t) {
    return Node(Type(std::move(t)));
}

} // namespace hilti
