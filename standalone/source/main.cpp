#include "resolver.hpp"

#include <asio.hpp>
#include "fmt/format.h"

auto reader(std::shared_ptr<tuposoft::resolver> resolver, asio::ip::tcp::socket socket) -> asio::awaitable<void> {
    for (;;) {
        auto buffer = asio::streambuf{};
        co_await async_read_until(socket, buffer, '\n', asio::use_awaitable);
        std::istream input(&buffer);
        std::string domain;
        input >> domain;
        for (auto result = co_await resolver->query<tuposoft::dns_record_e::MX>(domain);
             auto [preference, mx]: result) {
            auto message = fmt::format("Preference: {}, MX: {}\n", preference, mx);
            co_await socket.async_send(asio::buffer(message), asio::use_awaitable);
        }
    }
}

auto listener() -> asio::awaitable<void> {
    const auto executor = co_await asio::this_coro::executor;
    constexpr auto PORT_NUM = 55555;
    auto acceptor = asio::ip::tcp::acceptor{executor, {asio::ip::tcp::v4(), PORT_NUM}};
    auto resolver = std::make_shared<tuposoft::resolver>(executor);
    co_await resolver->connect("1.1.1.1");
    for (;;) {
        auto socket = co_await acceptor.async_accept(asio::use_awaitable);
        co_spawn(executor, reader(resolver, std::move(socket)), asio::detached);
    }
}

auto main() -> int {
    auto io_context = asio::io_context{};
    co_spawn(io_context, listener(), asio::detached);
    io_context.run();

    return {};
}
