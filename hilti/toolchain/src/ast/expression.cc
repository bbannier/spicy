// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <memory>

#include <hilti/ast/declarations/expression.h>
#include <hilti/ast/expression.h>
#include <hilti/ast/expressions/name.h>
#include <hilti/ast/type.h>
#include <hilti/ast/visitor.h>

using namespace hilti;

std::string Expression::_dump() const {
    return util::fmt("%s %s", (type()->isConstant() ? " (const)" : " (non-const)"),
                     (isResolved() ? " (resolved)" : " (not resolved)"));
}
