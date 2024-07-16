#include "resolver.hpp"

#include "boost/asio.hpp"
#include "gtest/gtest.h"

using namespace tuposoft;
using namespace boost::asio;

TEST(resolver_test, mx) {
    auto context = io_context{};
    co_spawn(
            context,
            []() -> awaitable<void> {
                auto resolv = resolver{co_await this_coro::executor};
                co_await resolv.connect("1.1.1.1");
                const auto result = co_await resolv.query<dns_record_e::MX>("tuposoft.com");
                EXPECT_EQ(result.size(), 1);
            },
            detached);
    context.run();
}
