#pragma once

#include "common.hpp"

namespace KyryloKupin {
    struct mx_rdata {
        std::uint16_t preference{};
        std::string mx;
    };

    auto operator==(const mx_rdata &, const mx_rdata &) -> bool;

    auto tie_mx_rdata(const mx_rdata &);
} // namespace tuposoft
