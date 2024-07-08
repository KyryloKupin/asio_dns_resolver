#include "dns_question.hpp"

#include <asio.hpp>

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

        // Write qtype and qclass
        const auto qtype_network = htons(static_cast<std::uint16_t>(question.qtype));
        const auto qclass_network = htons(question.qclass);

        output.write(reinterpret_cast<const char *>(&qtype_network), sizeof(qtype_network));
        output.write(reinterpret_cast<const char *>(&qclass_network), sizeof(qclass_network));

        return output;
    }

    auto operator>>(std::istream &input, dns_question &question) -> decltype(input) {
        question.qname = from_dns_label_format(input);

        const auto qtype_network = read_from_stream_and_copy<std::uint16_t>(input);
        const auto qclass_network = read_from_stream_and_copy<std::uint16_t>(input);

        question.qtype = static_cast<dns_record_e>(ntohs(qtype_network));
        question.qclass = ntohs(qclass_network);

        return input;
    }
} // namespace tuposoft
