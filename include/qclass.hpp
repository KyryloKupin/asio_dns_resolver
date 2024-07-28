#pragma once

#include <cstdint>

namespace KyryloKupin::asio::dns {
    enum struct qclass : std::uint8_t { INET = 1, CS, CH, HS };
} // namespace tuposoft
