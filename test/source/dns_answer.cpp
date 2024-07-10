#include "mx_rdata.hpp"

#include "gtest/gtest.h"

#include <span>
#include <spanstream>

TEST(dns_answer, parse_mx) {
    const tuposoft::mx_rdata expected = {1, "aspmx.l.google.com"};
    auto input = std::ispanstream{"\000\001\005aspmx\001l\006google\300\023"};
    const auto actual = tuposoft::parse_mx(input);
    ASSERT_EQ(expected, actual);
}
