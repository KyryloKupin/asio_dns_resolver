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
