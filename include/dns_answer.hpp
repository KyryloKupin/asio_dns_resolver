#pragma once

#include "dns_record_e.hpp"
#include "mx_rdata.hpp"

#include <variant>

namespace tuposoft {
    struct dns_answer {
        std::string name;
        dns_record_e type;
        std::uint16_t cls;
        std::uint32_t ttl;
        std::uint16_t rdlength;
        std::variant<std::vector<std::uint8_t>, std::vector<mx_rdata>> rdata;
    };

    auto operator>>(std::istream &input, dns_answer &answer) -> decltype(input);

    auto tie_dns_answer(const dns_answer &answer);

    auto operator==(const dns_answer &, const dns_answer &) -> bool;
} // namespace tuposoft
