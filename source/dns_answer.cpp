#include "dns_answer.hpp"

#include <iomanip>

using namespace tuposoft;

template<>
auto tuposoft::parse_rdata<dns_record_e::MX>(std::istream &input) -> rdata_t<dns_record_e::MX>::type {
    return {read_big_endian<std::uint16_t>(input), from_dns_label_format(input)};
}
template<>
auto tuposoft::parse_rdata<dns_record_e::A>(std::istream &input) -> rdata_t<dns_record_e::A>::type {
    constexpr auto IPV4_SIZE = 4;

    auto output = std::ostringstream{std::ios::binary};
    auto buffer = std::array<char, IPV4_SIZE>{};
    input.read(buffer.data(), buffer.size());

    for (const auto octet: buffer) {
        output << static_cast<int>(static_cast<unsigned char>(octet));
        output << '.';
    }

    auto result = output.str();
    result.pop_back();

    return result;
}
