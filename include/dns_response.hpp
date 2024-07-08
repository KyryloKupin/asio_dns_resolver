#pragma once

#include "dns_answer.hpp"
#include "dns_query.hpp"

#include <iostream>

namespace tuposoft {
    struct dns_response : dns_query {
        dns_answer answer;
    };

    auto tie_dns_response(const dns_response &);

    auto operator==(const dns_response &, const dns_response &) -> bool;

    auto operator>>(std::istream &input, dns_response &response) -> decltype(input);
} // namespace tuposoft
