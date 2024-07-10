#pragma once

#include "common.hpp"

namespace tuposoft {
    struct mx_rdata {
        std::uint16_t preference{};
        std::string mx;
    };

    auto operator==(const mx_rdata &, const mx_rdata &) -> bool;

    auto tie_mx_rdata(const mx_rdata &);

    auto operator>>(std::istream &input, mx_rdata &mx_rdata) -> decltype(input);

} // namespace tuposoft
