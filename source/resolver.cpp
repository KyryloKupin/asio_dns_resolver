#include "resolver.hpp"

using namespace tuposoft;

auto resolver::generate_id() -> decltype(generate_id()) {
    static std::random_device rand;
    static std::mt19937 gen(rand());
    return std::uniform_int_distribution<std::uint16_t>(0, std::numeric_limits<std::uint16_t>::max())(gen);
}

template<>
auto resolver::create_query<dns_record_e::PTR>(const std::string &name) {
    const auto qname = reverse_qname(name) + "in-addr.arpa";
    return dns_query{.header =
                             {
                                     .id = generate_id(),
                                     .rd = 0x01,
                                     .qdcount = 0x01,
                             },
                     .question = {
                             .qname = qname,
                             .qtype = dns_record_e::PTR,
                             .qclass = 0x01,
                     }};
}
