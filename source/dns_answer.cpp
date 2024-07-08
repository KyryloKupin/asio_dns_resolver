#include "dns_answer.hpp"

using namespace tuposoft;

auto tuposoft::tie_dns_answer(const dns_answer &answer) {
    return std::tie(answer.name, answer.type, answer.cls, answer.ttl, answer.rdlength, answer.rdata);
}

auto tuposoft::operator==(const dns_answer &first, const dns_answer &second) -> bool {
    return tie_dns_answer(first) == tie_dns_answer(second);
}

auto tuposoft::parse_mx(std::istream &input) -> std::vector<mx_rdata> {
    const auto current_pos = input.tellg();
    input.seekg(static_cast<std::streamoff>(message_byte_offsets::ANCOUNT));
    const auto ancount = read_big_endian<std::uint16_t>(input);
    input.seekg(current_pos);
    auto rdata = std::vector<mx_rdata>(ancount);

    for (auto i{0}; i < ancount; ++i) {
        rdata[i] = {read_big_endian<std::uint16_t>(input), from_dns_label_format(input)};
    }

    return rdata;
}

auto tuposoft::operator>>(std::istream &input, dns_answer &answer) -> decltype(input) {
    answer.name = from_dns_label_format(input);

    // Read type, cls, ttl, rdlength, and rdata
    const auto type_network = read_big_endian<std::uint16_t>(input);
    const auto cls_network = read_big_endian<std::uint16_t>(input);
    const auto ttl_network = read_big_endian<std::uint32_t>(input);
    const auto rdlength_network = read_big_endian<std::uint16_t>(input);

    answer.type = static_cast<dns_record_e>(type_network);
    answer.cls = cls_network;
    answer.ttl = ttl_network;
    answer.rdlength = rdlength_network;

    switch (answer.type) {
        case dns_record_e::A:
        case dns_record_e::NS:
        case dns_record_e::CNAME:
        case dns_record_e::SOA:
        case dns_record_e::PTR:
        case dns_record_e::MX:
            answer.rdata = parse_mx(input);
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
