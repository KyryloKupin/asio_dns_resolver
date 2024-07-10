#include "dns_answer.hpp"

#include <tuple>

using namespace tuposoft;

auto tuposoft::tie_dns_answer(const dns_answer &answer) {
    return std::tie(answer.name, answer.type, answer.cls, answer.ttl, answer.rdlength, answer.rdata);
}

auto tuposoft::operator==(const dns_answer &first, const dns_answer &second) -> bool {
    return tie_dns_answer(first) == tie_dns_answer(second);
}

auto tuposoft::operator>>(std::istream &input, dns_answer &answer) -> decltype(input) {
    answer.name = from_dns_label_format(input);
    answer.type = static_cast<dns_record_e>(read_big_endian<std::uint16_t>(input));
    answer.cls = read_big_endian<std::uint16_t>(input);
    answer.ttl = read_big_endian<std::uint32_t>(input);
    answer.rdlength = read_big_endian<std::uint16_t>(input);

    switch (answer.type) {
        case dns_record_e::A:
        case dns_record_e::NS:
        case dns_record_e::CNAME:
        case dns_record_e::SOA:
        case dns_record_e::PTR:
        case dns_record_e::MX:
            answer.rdata = mx_rdata{read_big_endian<std::uint16_t>(input), from_dns_label_format(input)};
            break;
        case dns_record_e::TXT:
        case dns_record_e::AAAA:
        case dns_record_e::SRV:
        case dns_record_e::OPT:
        case dns_record_e::DS:
        case dns_record_e::RRSIG:
        case dns_record_e::NSEC:
        case dns_record_e::DNSKEY:
            break;
    }

    return input;
}
