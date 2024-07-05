#include "dns.hpp"

#include <gtest/gtest.h>

constexpr auto STRING_TERMINATOR = '\0';

struct dns_test : testing::Test {
protected:
    std::vector<std::uint8_t> dns_label_format = {static_cast<uint8_t>(label_length::tuposoft_length),
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

    std::vector<std::uint8_t> dns_query = {
            0x16, 0x6a, 0x01, 0x20, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x08, 0x74,
            0x75, 0x70, 0x6f, 0x73, 0x6f, 0x66, 0x74, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x0f,
            0x00, 0x01, 0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };

    tuposoft::dns_header dns_header{
            .id = ntohs(0x6a16),
            .rd = 1,
            .ad = 1,
            .qdcount = 1,
            .arcount = 1,
    };

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

TEST_F(dns_test, dns_header_deserialization) {
    std::istringstream input{{dns_query.begin(), dns_query.end()}};
    tuposoft::dns_header actual;
    input >> actual;
    ASSERT_EQ(dns_header, actual);
}

TEST_F(dns_test, dns_header_serialization) {
    std::ostringstream output{std::ios::binary};
    output << dns_header;
    const auto expected = std::string{dns_query.begin(), dns_query.begin() + 12};
    ASSERT_EQ(output.str(), expected);
}
