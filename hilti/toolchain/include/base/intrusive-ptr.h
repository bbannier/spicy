// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>

#include <hilti/rt/intrusive-ptr.h>

namespace hilti {

template<class T>
using IntrusivePtr = hilti::rt::IntrusivePtr<T>;

namespace intrusive_ptr {
using AdoptRef = ::hilti::rt::intrusive_ptr::AdoptRef;
using NewRef = ::hilti::rt::intrusive_ptr::NewRef;
using ManagedObject = ::hilti::rt::intrusive_ptr::ManagedObject;
} // namespace intrusive_ptr

using rt::cast_intrusive;
using rt::make_intrusive;

} // namespace hilti
