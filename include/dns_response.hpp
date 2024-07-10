#pragma once

#include "dns_answer.hpp"
#include "dns_query.hpp"

#include <iostream>

namespace tuposoft {
    struct dns_response : dns_query {
        std::vector<dns_answer> answers;
    };

    auto tie_dns_response(const dns_response &);

    auto operator==(const dns_response &, const dns_response &) -> bool;

    auto operator>>(std::istream &input, dns_response &response) -> decltype(input);
} // namespace tuposoft
