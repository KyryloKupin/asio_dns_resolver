#pragma once

#include "dns_query.hpp"
#include "dns_record_e.hpp"
#include "dns_response.hpp"

#include "boost/asio.hpp"

#include <random>

using namespace boost;

namespace tuposoft {
    class resolver {
    public:
        explicit resolver(const asio::any_io_executor &executor) : socket_(executor) {}

        auto connect(const std::string server) -> asio::awaitable<void> {
            constexpr auto DNS_PORT = 53;
            co_await socket_.async_connect({asio::ip::address::from_string(server), DNS_PORT}, asio::use_awaitable);
        }

        template<dns_record_e T>
        auto query(const std::string domain) -> asio::awaitable<std::vector<dns_answer<T>>> {
            const auto query = create_query<T>(domain);
            asio::streambuf buf;
            std::ostream out(&buf);
            out << query;
            co_await socket_.async_send(buffer(buf.data(), buf.size()), asio::use_awaitable);
            out.flush();

            auto input = std::array<char, 1024>{};
            const auto reply = co_await socket_.async_receive(asio::buffer(input), asio::use_awaitable);

            auto dns_response = tuposoft::dns_response<T>{};
            auto instream = std::istringstream{{input.begin(), input.end()}, std::ios::binary};
            instream >> dns_response;

            co_return dns_response.answers;
        };

    private:
        static auto generate_id() -> unsigned short;

        template<dns_record_e type>
        static auto create_query(const std::string &domain) {
            return dns_query{.header =
                                     {
                                             .id = generate_id(),
                                             .rd = 0x01,
                                             .qdcount = 0x01,
                                     },
                             .question = {
                                     .qname = domain,
                                     .qtype = type,
                                     .qclass = 0x01,
                             }};
        };

        asio::ip::udp::socket socket_;
    };
} // namespace tuposoft
