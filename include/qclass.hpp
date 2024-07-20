#pragma once

#include <cstdint>

namespace tuposoft {
    enum struct qclass : std::uint8_t {
        IN = 1,
        CS = 2,
        CH = 3,
        HS = 4,
        ANY = 255,
    };
} // namespace tuposoft
