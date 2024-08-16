#pragma once

#include "boost/asio/use_awaitable.hpp"
#include "boost/system/detail/errc.hpp"
#include "dns_query.hpp"
#include "dns_response.hpp"
#include "qtype.hpp"

#include "boost/asio.hpp"
#include "boost/asio/experimental/parallel_group.hpp"

#include <random>
#include <sstream>
#include <typeinfo>

#include <fmt/core.h>

namespace kyrylokupin::asio::dns {
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
            static constexpr auto timeout_seconds = 10;
            static constexpr auto input_buffer_size = 1024;
            const auto query = create_query<T>(domain);
            auto buf = asio::streambuf{};
            auto out = std::ostream{&buf};
            out << query;
            co_await socket_.async_send(buffer(buf.data(), buf.size()), asio::use_awaitable);

            auto input = std::array<char, input_buffer_size>{};
            auto timer = asio::steady_timer{co_await asio::this_coro::executor};
            timer.expires_after(std::chrono::seconds(timeout_seconds));
            auto receive = socket_.async_receive(asio::buffer(input), asio::use_awaitable);
            auto wait = timer.async_wait(asio::use_awaitable);

            auto [receive_result, receive_ec, wait_result, wait_ec] =
                    co_await asio::experimental::make_parallel_group(
                            [&](auto token) { return socket_.async_receive(asio::buffer(input), token); },
                            [&](auto token) { return timer.async_wait(token); })
                            .async_wait(boost::asio::experimental::wait_for_one(), asio::use_awaitable);
            if (receive_ec == boost::system::errc::success) {
                auto dns_response = kyrylokupin::asio::dns::dns_response<T>{};
                auto instream = std::istringstream{{input.begin(), input.end()}, std::ios::binary};
                instream >> dns_response;
                co_return dns_response.answers;
            } else {
                throw std::runtime_error(
                        fmt::format("Timeout while waiting for UDP response, error code: {} error value: {}",
                                    receive_ec.value(), receive_ec.message()));
            }
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
} // namespace kyrylokupin::asio::dns
