#pragma once

#include "dns_record_e.hpp"
#include "mx_rdata.hpp"

#include <array>
#include <sstream>
#include <tuple>

namespace tuposoft {
    template<dns_record_e>
    struct rdata {
        using type = void;
    };

    template<>
    struct rdata<dns_record_e::MX> {
        using type = mx_rdata;
    };

    template<>
    struct rdata<dns_record_e::A> {
        using type = std::string;
    };

    template<dns_record_e T>
    struct dns_answer {
        std::string name;
        dns_record_e type = T;
        std::uint16_t cls{};
        std::uint32_t ttl{};
        std::uint16_t rdlength{};
        typename rdata<T>::type rdata;
    };

    template<dns_record_e T>
    auto parse_rdata(std::istream &) -> typename rdata<T>::type;

    template<>
    auto parse_rdata<dns_record_e::MX>(std::istream &input) -> rdata<dns_record_e::MX>::type;

    template<>
    auto parse_rdata<dns_record_e::A>(std::istream &input) -> rdata<dns_record_e::A>::type;

    template<dns_record_e T>
    auto operator>>(std::istream &input, dns_answer<T> &answer) -> decltype(input) {
        answer.name = from_dns_label_format(input);
        answer.type = static_cast<dns_record_e>(read_big_endian<std::uint16_t>(input));
        answer.cls = read_big_endian<std::uint16_t>(input);
        answer.ttl = read_big_endian<std::uint32_t>(input);
        answer.rdlength = read_big_endian<std::uint16_t>(input);
        answer.rdata = parse_rdata<T>(input);

        return input;
    };

    template<dns_record_e T>
    auto tie_dns_answer(const dns_answer<T> &answer) {
        return std::tie(answer.name, answer.type, answer.cls, answer.ttl, answer.rdlength, answer.rdata);
    };

    template<dns_record_e T>
    auto operator==(const dns_answer<T> &first, const dns_answer<T> &second) -> bool {
        return tie_dns_answer(first) == tie_dns_answer(second);
    };
} // namespace tuposoft
