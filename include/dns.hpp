#pragma once

#include <cstddef>
#include <cstdint>
#include <iostream>
#include <string>
#include <tuple>
#include <variant>
#include <vector>

namespace tuposoft {
    // Convert domain name to DNS label format
    auto to_dns_label_format(const std::string &domain) -> std::vector<std::uint8_t>;

    // Convert from DNS label format to domain name
    auto from_dns_label_format(std::istream &input) -> std::string;

    template<typename T>
    auto read_from_stream_and_copy(std::istream &input) -> T;

    template<typename T = std::uint16_t>
    auto read_big_endian(std::istream &input) -> T;

    struct dns_header {
        std::uint16_t id{}; // Identification

        std::uint8_t rd : 1 {1}; // Recursion Desired
        std::uint8_t tc : 1 {}; // Truncated Message
        std::uint8_t aa : 1 {}; // Authoritative Answer
        std::uint8_t opcode : 4 {}; // Opcode
        std::uint8_t qr : 1 {}; // Query/Response uint8_t

        std::uint8_t rcode : 4 {}; // Response Code
        std::uint8_t cd : 1 {}; // Checking Disabled
        std::uint8_t ad : 1 {}; // Authenticated Data
        std::uint8_t z : 1 {}; // Reserved
        std::uint8_t ra : 1 {}; // Recursion Available

        std::uint16_t qdcount{1}; // Number of question entries
        std::uint16_t ancount{}; // Number of answer entries
        std::uint16_t nscount{}; // Number of authority entries
        std::uint16_t arcount{}; // Number of resource entries

        auto operator==(const dns_header &other) const -> bool;

    private:
        [[nodiscard]] auto tied() const {
            return std::tie(id, rd, tc, aa, opcode, qr, rcode, cd, ad, z, ra, qdcount, ancount, nscount, arcount);
        }
    };

    auto operator>>(std::istream &input, dns_header &header) -> decltype(input);

    auto operator<<(std::ostream &output, const dns_header &header) -> decltype(output);

    enum struct dns_record_e : std::uint8_t {
        A = 1, // IPv4 address record
        NS = 2, // Delegates a DNS zone to use the given authoritative name servers
        CNAME = 5, // Canonical name record
        SOA = 6, // Start of [a zone of] authority record
        PTR = 12, // Pointer record
        MX = 15, // Mail exchange record
        TXT = 16, // Arbitrary text record
        AAAA = 28, // IPv6 address record
        SRV = 33, // Service locator
        OPT = 41, // Option record
        DS = 43, // Delegation signer
        RRSIG = 46, // DNSSEC signature
        NSEC = 47, // Next-secure record
        DNSKEY = 48 // DNSSEC public key
    };

    // Overload << operator for dns_record_e
    auto operator<<(std::ostream &out, dns_record_e record) -> decltype(out);

    // Overload >> operator for dns_record_e
    auto operator>>(std::istream &ins, dns_record_e &record) -> decltype(ins);

    auto read_name(const std::vector<std::uint8_t> &data, std::size_t &offset) -> std::string;

    struct dns_question {
        std::string qname;
        dns_record_e qtype;
        std::uint16_t qclass{1};

        auto operator==(const dns_question &other) const -> bool;

    private:
        [[nodiscard]] auto tied() const { return std::tie(qname, qtype, qclass); }
    };

    // Overload << operator to write data to stream
    auto operator<<(std::ostream &output, const dns_question &question) -> decltype(output);

    // Overload >> operator to read data from stream
    auto operator>>(std::istream &input, dns_question &question) -> decltype(input);

    struct mx_rdata {
        std::uint16_t preference;
        std::string mx;

        auto operator==(const mx_rdata &) const -> bool;

    private:
        [[nodiscard]] auto tied() const { return std::tie(preference, mx); }
    };

    auto operator>>(std::istream &input, mx_rdata &mx_rdata) -> decltype(input);

    struct dns_answer {
        std::string name;
        dns_record_e type;
        std::uint16_t cls;
        std::uint32_t ttl;
        std::uint16_t rdlength;
        std::variant<std::vector<std::uint8_t>, std::vector<mx_rdata>> rdata;

        auto operator==(const dns_answer &) const -> bool;

    private:
        [[nodiscard]] auto tied() const { return std::tie(name, type, cls, ttl, rdlength, rdata); }
    };


    // Overload << operator to write data to stream
    //    auto operator<<(std::ostream &output, const dns_answer &answer) -> decltype(output);

    // Overload >> operator to read data from stream
    auto operator>>(std::istream &input, dns_answer &answer) -> decltype(input);

    struct dns_query {
        dns_header header;
        dns_question question;

        auto operator==(const dns_query &) const -> bool;

    private:
        [[nodiscard]] auto tied() const { return std::tie(header, question); }
    };

    auto operator<<(std::ostream &output, const dns_query &request) -> decltype(output);

    auto operator>>(std::istream &input, dns_query &request) -> decltype(input);

    struct dns_response : dns_query {
        dns_answer answer;

        auto operator==(const dns_response &) const -> bool;

        friend auto operator>>(std::istream &input, dns_response &response) -> decltype(input);

    private:
        [[nodiscard]] auto tied() const { return std::tie(header, question, answer); }

        auto parse_mx(std::istream &input);
    };
} // namespace tuposoft
