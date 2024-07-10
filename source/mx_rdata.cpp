#include "mx_rdata.hpp"

#include <tuple>

namespace tuposoft {
    auto tie_mx_rdata(const mx_rdata &rdata) { return std::tie(rdata.preference, rdata.mx); }

    auto operator>>(std::istream &input, mx_rdata &mx_rdata) -> decltype(input) {
        mx_rdata.preference = read_big_endian<std::uint16_t>(input);
        mx_rdata.mx = from_dns_label_format(input);
        return input;
    }

    auto operator==(const mx_rdata &first, const mx_rdata &second) -> bool {
        return tie_mx_rdata(first) == tie_mx_rdata(second);
    }

    auto parse_mx(std::istream &input) -> mx_rdata {
        return {read_big_endian<std::uint16_t>(input), from_dns_label_format(input)};
    }
} // namespace tuposoft
