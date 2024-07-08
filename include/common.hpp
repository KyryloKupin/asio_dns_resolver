#pragma once

#include <cstdint>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>

namespace tuposoft {
    constexpr auto BYTE_SIZE = std::uint8_t{0x08U};
    constexpr auto FULL_BYTE = std::uint8_t{0xFF};
    constexpr auto UPPER_SIX_BITS_MASK = std::uint8_t{0xC0U};

    auto to_dns_label_format(const std::string &domain) -> std::vector<std::uint8_t>;

    auto from_dns_label_format(std::istream &input) -> std::string;

    template<typename T>
    auto read_from_stream_and_copy(std::istream &input) -> T {
        std::array<char, sizeof(T)> buffer{};
        input.read(buffer.data(), sizeof(T));

        T object{};
        std::memcpy(&object, buffer.data(), sizeof(T));

        return object;
    }

    template<typename T = std::uint16_t>
    auto read_big_endian(std::istream &input) -> T {
        T result{};
        for (int i = 0; i < sizeof(T); ++i) {
            result <<= BYTE_SIZE;
            result |= static_cast<T>(input.get()) & FULL_BYTE;
        }
        return result;
    }

    enum struct message_byte_offsets : std::uint8_t {
        HEADER = 0,
        ANCOUNT = 6,
        QUESTION = 12,
        ANSWERS = 30,
    };
} // namespace tuposoft
