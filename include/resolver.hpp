#pragma once

#include "dns_query.hpp"
#include "dns_response.hpp"
#include "qtype.hpp"

#include "boost/asio.hpp"

#include <random>
#include <sstream>

namespace KyryloKupin::asio::dns {
    namespace asio = boost::asio;

    class resolver {
    public:
        explicit resolver(const asio::any_io_executor &executor) : socket_(executor) {}

        auto connect(const std::string server) -> asio::awaitable<void> {
            constexpr auto DNS_PORT = 53;
            co_await socket_.async_connect({asio::ip::address::from_string(server), DNS_PORT}, asio::use_awaitable);
        }

        template<qtype T>
        auto query(const std::string domain) -> asio::awaitable<std::vector<dns_answer<T>>> {
            const auto query = create_query<T>(domain);
            auto buf = asio::streambuf{};
            auto out = std::ostream{&buf};
            out << query;
            co_await socket_.async_send(buffer(buf.data(), buf.size()), asio::use_awaitable);

            auto input = std::array<char, 1024>{};
            co_await socket_.async_receive(asio::buffer(input), asio::use_awaitable);

            auto dns_response = KyryloKupin::asio::dns::dns_response<T>{};
            auto instream = std::istringstream{{input.begin(), input.end()}, std::ios::binary};
            instream >> dns_response;

            co_return dns_response.answers;
        }

    private:
        static auto generate_id() -> std::uint16_t;

        template<qtype T>
        auto create_query(const std::string &name) {
            return dns_query{.header =
                                     {
                                             .id = generate_id(),
                                             .rd = 0x01,
                                             .qdcount = 0x01,
                                     },
                             .question = {
                                     .qname = name,
                                     .type = T,
                                     .cls = qclass::INET,
                             }};
        }

        static auto reverse_qname(const std::string &name) -> std::string {
            auto iss = std::istringstream{name};
            auto segment = std::string{};
            auto segments = std::vector<std::string>{};

            while (std::getline(iss, segment, '.')) {
                segments.push_back(segment);
            }

            std::reverse(segments.begin(), segments.end());

            auto reversed_ip = std::string{};
            for (const auto &seg: segments) {
                reversed_ip += seg + '.';
            }

            return reversed_ip;
        }

        asio::ip::udp::socket socket_;
    };

    template<>
    inline auto resolver::create_query<qtype::PTR>(const std::string &name) {
        const auto qname = reverse_qname(name) + "in-addr.arpa";
        return dns_query{.header =
                                 {
                                         .id = generate_id(),
                                         .rd = 0x01,
                                         .qdcount = 0x01,
                                 },
                         .question = {
                                 .qname = qname,
                                 .type = qtype::PTR,
                                 .cls = qclass::INET,
                         }};
    }
} // namespace KyryloKupin::asio::dns
