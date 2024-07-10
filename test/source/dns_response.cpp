#include "dns_response.hpp"

#include "gtest/gtest.h"

#include <span>

using namespace tuposoft;

TEST(dns_response, parse_mx) {
    constexpr auto RESPONSE_ID = 0x276f;
    constexpr auto TTL = 300;
    std::vector<dns_answer<dns_record_e::MX>> EXPECTED_DNS_RESPONSE_ANSWERS = {
            {"cience.com", dns_record_e::MX, 1, TTL, 19,
             mx_rdata{
                     1,
                     "aspmx.l.google.com",
             }},
            {"cience.com", dns_record_e::MX, 1, TTL, 9,
             mx_rdata{
                     10,
                     "alt3.aspmx.l.google.com",
             }},
            {"cience.com", dns_record_e::MX, 1, TTL, 9,
             mx_rdata{
                     10,
                     "alt4.aspmx.l.google.com",
             }},
            {"cience.com", dns_record_e::MX, 1, TTL, 9,
             mx_rdata{
                     5,
                     "alt1.aspmx.l.google.com",
             }},
            {"cience.com", dns_record_e::MX, 1, TTL, 9,
             mx_rdata{
                     5,
                     "alt2.aspmx.l.google.com",
             }},
    };
    auto EXPECTED_DNS_RESPONSE = dns_response{{
                                                      .header =
                                                              {
                                                                      .id = RESPONSE_ID,
                                                                      .rd = 1,
                                                                      .qr = 1,
                                                                      .ra = 1,
                                                                      .qdcount = 1,
                                                                      .ancount = 5,
                                                                      .nscount = 0,
                                                                      .arcount = 1,
                                                              },
                                                      .question =
                                                              {
                                                                      .qname = "cience.com",
                                                                      .qtype = dns_record_e::MX,
                                                                      .qclass = 1,
                                                              },
                                              },
                                              EXPECTED_DNS_RESPONSE_ANSWERS};

    auto span = std::span{
            "'o\201\200\000\001\000\005\000\000\000\001\006cience\003com\000\000\017\000\001\300\f\000\017\000\001\000"
            "\000\001,\000\023\000\001\005aspmx\001l\006google\300\023\300\f\000\017\000\001\000\000\001,"
            "\000\t\000\n\004alt3\300*\300\f\000\017\000\001\000\000\001,\000\t\000\n\004alt4\300*"
            "\300\f\000\017\000\001\000\000\001,\000\t\000\005\004alt1\300*\300\f\000\017\000\001\000\000\001,"
            "\000\t\000\005\004alt2\300*\000\000)\004\320\000\000\000\000\000\000"};

    auto input = std::istringstream{{span.begin(), span.end()}, std::ios::binary};

    auto actual_dns_response = dns_response<dns_record_e::MX>{};
    input >> actual_dns_response;

    ASSERT_EQ(EXPECTED_DNS_RESPONSE.header, actual_dns_response.header) << "The header doesn't match!";
    ASSERT_EQ(EXPECTED_DNS_RESPONSE.question, actual_dns_response.question) << "The question doesn't match!";
    ASSERT_EQ(EXPECTED_DNS_RESPONSE.answers, actual_dns_response.answers) << "The answers don't match!";
}
