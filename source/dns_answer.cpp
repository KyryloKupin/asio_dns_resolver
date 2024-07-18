#include "dns_answer.hpp"

using namespace tuposoft;

template<>
auto tuposoft::parse_rdata<dns_record_e::MX>(std::istream &input) -> rdata<dns_record_e::MX>::type {
    return {read_big_endian<std::uint16_t>(input), from_dns_label_format(input)};
}

template<>
auto tuposoft::parse_rdata<dns_record_e::A>(std::istream &input) -> rdata<dns_record_e::A>::type {
    constexpr auto IPV4_SIZE = 4;

    auto binary_ipv4 = std::array<char, IPV4_SIZE>{};
    input.read(binary_ipv4.data(), binary_ipv4.size());

    auto str_ipv4 = std::array<char, INET_ADDRSTRLEN>{};
    inet_ntop(AF_INET, binary_ipv4.data(), str_ipv4.data(), str_ipv4.size());

    return str_ipv4.data();
}

template<>
auto tuposoft::parse_rdata<dns_record_e::AAAA>(std::istream &input) -> rdata<dns_record_e::AAAA>::type {
    constexpr auto IPV6_SIZE = 16;

    auto binary_ipv6 = std::array<char, IPV6_SIZE>{};
    input.read(binary_ipv6.data(), binary_ipv6.size());

    auto str_ipv6 = std::array<char, INET6_ADDRSTRLEN>{};
    inet_ntop(AF_INET6, binary_ipv6.data(), str_ipv6.data(), str_ipv6.size());

    return str_ipv6.data();
}

template<>
auto tuposoft::parse_rdata<dns_record_e::SOA>(std::istream &input) -> rdata<dns_record_e::SOA>::type {
    return {
            from_dns_label_format(input),          from_dns_label_format(input),
            read_big_endian<std::uint32_t>(input), read_big_endian<std::uint32_t>(input),
            read_big_endian<std::uint32_t>(input), read_big_endian<std::uint32_t>(input),
            read_big_endian<std::uint32_t>(input),
    };
}
