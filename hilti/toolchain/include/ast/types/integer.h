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
    IntegerBase(const std::type_info& type_info, Wildcard /*unused*/, Meta m = Meta())
        : Type(type_info, std::move(m)),
          trait::isAllocable(&_traits()),
          trait::isParameterized(&_traits()),
          _wildcard(true) {}
    IntegerBase(const std::type_info& type_info, int width, Meta m = Meta())
        : Type(type_info, std::move(m)),
          trait::isAllocable(&_traits()),
          trait::isParameterized(&_traits()),
          _width(width) {}
    IntegerBase(const std::type_info& type_info, Meta m = Meta())
        : Type(type_info, std::move(m)), trait::isAllocable(&_traits()), trait::isParameterized(&_traits()) {}

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
    SignedInteger(Wildcard w, Meta m = hilti::Meta()) : detail::IntegerBase(typeid(SignedInteger), w, std::move(m)) {}
    SignedInteger(int width, Meta m = hilti::Meta()) : detail::IntegerBase(typeid(SignedInteger), std::move(m)) {}
    SignedInteger(Meta m = hilti::Meta()) : detail::IntegerBase(typeid(SignedInteger), std::move(m)) {}

    bool operator==(const SignedInteger& other) const { return width() == other.width(); }

    /** Implements the `Type` interface. */
    std::vector<Node> typeParameters() const override;

    /** Implements the `Node` interface. */
    auto isEqual(const Type& other) const { return node::isEqual(this, other); }
};

/** AST node for an unsigned integer type. */
class UnsignedInteger : public detail::IntegerBase {
public:
    UnsignedInteger(Wildcard w, Meta m = hilti::Meta())
        : detail::IntegerBase(typeid(UnsignedInteger), w, std::move(m)) {}
    UnsignedInteger(int width, Meta m = hilti::Meta()) : detail::IntegerBase(typeid(UnsignedInteger), std::move(m)) {}
    UnsignedInteger(Meta m = hilti::Meta()) : detail::IntegerBase(typeid(UnsignedInteger), std::move(m)) {}

    bool operator==(const UnsignedInteger& other) const { return width() == other.width(); }

    /** Implements the `Type` interface. */
    std::vector<Node> typeParameters() const override;

    /** Implements the `Node` interface. */
    auto isEqual(const Type& other) const { return node::isEqual(this, other); }
};

} // namespace hilti::type
