// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <type_traits>

#include <hilti/rt/logging.h>
#include <hilti/rt/util.h>

using namespace hilti::rt;
using namespace hilti::rt::detail;

#include <cstdlib>
#include <iostream>
#include <utility>


using namespace hilti::rt;

detail::DebugLogger::DebugLogger(hilti::rt::filesystem::path output) : _path(std::move(output)) {}

void detail::DebugLogger::enable(std::string_view streams) {
    for ( auto s : split(streams, ":") )
        _streams[trim(s)] = 0;
}

void detail::DebugLogger::print(std::string_view stream, std::string_view msg) {
    if ( _path.empty() )
        return;

    auto i = _streams.find(stream);
    if ( i == _streams.end() )
        return;

    if ( ! _output ) {
        if ( _path == "/dev/stdout" )
            _output = &std::cout;
        else if ( _path == "/dev/stderr" )
            _output = &std::cerr;
        else {
            _output_file = std::make_unique<std::ofstream>(_path, std::ios::out | std::ios::trunc);
            if ( ! _output_file->is_open() )
                warning(fmt("libhilti: cannot open file '%s' for debug output", _path));

            _output = _output_file.get();
        }
    }

    // Theoretically the ident computation could overflow, but in that case we
    // would have already run into trouble elsewhere (e.g., giant strings from
    // huge ident widths). Instead perform the computation with overflow which
    // for unsigned integers is defined and wraps around.
    static_assert(std::is_unsigned_v<std::remove_reference_t<decltype(i->second.Ref())>>);
    auto indent = std::string(i->second.Ref() * 2, ' ');
    (*_output) << fmt("[%s] %s%s", stream, indent, msg) << '\n';
    _output->flush();
}
