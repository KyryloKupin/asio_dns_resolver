#include "dns_answer.hpp"

#include "gtest/gtest.h"

#include <span>

using namespace tuposoft;

TEST(dns_answer, parse_rdata_a) {
    constexpr auto expected = "178.151.191.58";
    auto span = std::span{"\262\227\277:"};
    auto input = std::istringstream{{span.begin(), span.end()}, std::ios::binary};
    const auto actual = parse_rdata<dns_record_e::A>(input);
    ASSERT_EQ(expected, actual);
}

TEST(dns_answer, parse_rdata_aaaa) {
    constexpr auto expected = "2606:2800:21f:cb07:6820:80da:af6b:8b2c";
    auto span = std::span{"&\006(\000\002\037\313\ah \200\332\257k\213,"};
    auto input = std::istringstream{{span.begin(), span.end()}, std::ios::binary};
    const auto actual = parse_rdata<dns_record_e::AAAA>(input);
    ASSERT_EQ(expected, actual);
}
