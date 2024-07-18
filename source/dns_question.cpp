#include "dns_question.hpp"

#include <boost/asio.hpp>

namespace tuposoft {
    auto tie_dns_question(const dns_question &question) {
        return std::tie(question.qname, question.qtype, question.qclass);
    }

    auto operator==(const dns_question &first, const dns_question &second) -> bool {
        return tie_dns_question(first) == tie_dns_question(second);
    }

    auto operator<<(std::ostream &output, const dns_question &question) -> decltype(output) {
        const auto label_format = to_dns_label_format(question.qname);
        output.write(std::string{label_format.begin(), label_format.end()}.c_str(),
                     static_cast<std::streamsize>(label_format.size()));

        write_big_endian(output, static_cast<std::uint16_t>(question.qtype));
        write_big_endian(output, question.qclass);

        return output;
    }

    auto operator>>(std::istream &input, dns_question &question) -> decltype(input) {
        question.qname = from_dns_label_format(input);
        question.qtype = static_cast<qtype>(read_big_endian(input));
        question.qclass = read_big_endian(input);

        return input;
    }
} // namespace tuposoft
