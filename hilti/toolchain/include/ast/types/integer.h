// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>
#include <vector>

#include <hilti/ast/type.h>

namespace hilti::type {

namespace detail {

/** Base class for an AST node representing an integer type. */
class IntegerBase : public hilti::Type, trait::isAllocable, trait::isParameterized {
public:
    IntegerBase(Wildcard /*unused*/, Meta m = Meta())
        : Type(std::move(m)), trait::isAllocable(&_traits()), trait::isParameterized(&_traits()), _wildcard(true) {}
    IntegerBase(int width, Meta m = Meta())
        : Type(std::move(m)), trait::isAllocable(&_traits()), trait::isParameterized(&_traits()), _width(width) {}
    IntegerBase(Meta m = Meta())
        : Type(std::move(m)), trait::isAllocable(&_traits()), trait::isParameterized(&_traits()) {}

    auto width() const { return _width; }

    /** Implements the `Type` interface. */
    bool isWildcard() const override { return _wildcard; }
    /** Implements the `Type` interface. */
    bool _isResolved(ResolvedState* rstate) const override { return true; }
    /** Implements the `Node` interface. */
    node::Properties properties() const override { return node::Properties{{"width", _width}}; }

private:
    bool _wildcard = false;
    int _width = 0;
};

} // namespace detail

/** AST node for a signed integer type. */
class SignedInteger : public detail::IntegerBase {
public:
    using detail::IntegerBase::IntegerBase;

    bool operator==(const SignedInteger& other) const { return width() == other.width(); }

    /** Implements the `Type` interface. */
    std::vector<Node> typeParameters() const override;

    /** Implements the `Node` interface. */
    auto isEqual(const Type& other) const { return node::isEqual(this, other); }
};

/** AST node for an unsigned integer type. */
class UnsignedInteger : public detail::IntegerBase {
public:
    using detail::IntegerBase::IntegerBase;

    bool operator==(const UnsignedInteger& other) const { return width() == other.width(); }

    /** Implements the `Type` interface. */
    std::vector<Node> typeParameters() const override;

    /** Implements the `Node` interface. */
    auto isEqual(const Type& other) const { return node::isEqual(this, other); }
};

} // namespace hilti::type
