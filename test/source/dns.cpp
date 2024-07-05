#include "dns.hpp"

#include <gtest/gtest.h>

#include <spanstream>

constexpr auto STRING_TERMINATOR = '\0';

struct dns_test : testing::Test {
protected:
    std::vector<uint8_t> dns_label_format = {static_cast<uint8_t>(label_length::tuposoft_length),
                                             't',
                                             'u',
                                             'p',
                                             'o',
                                             's',
                                             'o',
                                             'f',
                                             't',
                                             static_cast<uint8_t>(label_length::com_length),
                                             'c',
                                             'o',
                                             'm',
                                             STRING_TERMINATOR};

    std::string domain = "tuposoft.com";

private:
    enum class label_length : uint8_t {
        tuposoft_length = 8,
        com_length = 3,
    };
};

TEST_F(dns_test, to_dns_label_format) {
    const auto actual = tuposoft::to_dns_label_format(domain);
    ASSERT_EQ(dns_label_format, actual);
}

TEST_F(dns_test, from_dns_label_format) {
    std::istringstream input{{dns_label_format.begin(), dns_label_format.end()}};
    const auto actual = tuposoft::from_dns_label_format(input);
    ASSERT_EQ(domain, actual);
}
