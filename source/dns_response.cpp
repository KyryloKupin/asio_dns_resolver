#include "dns_response.hpp"

#include <asio.hpp>

#include <cstring>
#include <istream>

namespace tuposoft {
    auto tie_dns_response(const dns_response &response) {
        return std::tie(response.header, response.question, response.answers);
    }

    auto operator==(const dns_response &first, const dns_response &second) -> bool {
        return tie_dns_response(first) == tie_dns_response(second);
    }

    auto operator>>(std::istream &input, dns_response &response) -> decltype(input) {
        input >> response.header;
        input >> response.question;

        const auto ancount = response.header.ancount;
        response.answers = std::vector<dns_answer>(ancount);

        for (int i = 0; i < ancount; ++i) {
            auto answer = dns_answer{};
            input >> answer;
            response.answers[i] = answer;
        }

        return input;
    }
} // namespace tuposoft
