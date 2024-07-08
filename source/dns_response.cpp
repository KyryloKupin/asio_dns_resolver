#include "dns_response.hpp"

#include <asio.hpp>

#include <cstring>
#include <istream>

namespace tuposoft {
    auto tie_dns_response(const dns_response &response) {
        return std::tie(response.header, response.question, response.answer);
    }

    auto operator==(const dns_response &first, const dns_response &second) -> bool {
        return tie_dns_response(first) == tie_dns_response(second);
    }


    auto operator>>(std::istream &input, dns_response &response) -> decltype(input) {
        input >> response.header;
        input >> response.question;
        input >> response.answer;

        return input;
    }
} // namespace tuposoft
