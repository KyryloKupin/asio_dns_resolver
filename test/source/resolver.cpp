#include "resolver.hpp"

#include "boost/asio.hpp"
#include "gtest/gtest.h"

using namespace tuposoft;
using namespace boost::asio;

class resolver_test : public ::testing::Test {
protected:
    io_context context_;
};

TEST_F(resolver_test, a) {
    co_spawn(
            context_,
            []() -> awaitable<void> {
                auto resolv = resolver{co_await this_coro::executor};
                co_await resolv.connect("1.1.1.1");
                const auto result = co_await resolv.query<dns_record_e::A>("tuposoft.com");
                EXPECT_EQ(result.size(), 1);
                EXPECT_EQ(result[0].rdata, "178.151.191.58");
            },
            detached);
    context_.run();
}

TEST_F(resolver_test, mx) {
    co_spawn(
            context_,
            []() -> awaitable<void> {
                auto resolv = resolver{co_await this_coro::executor};
                co_await resolv.connect("1.1.1.1");
                const auto result = co_await resolv.query<dns_record_e::MX>("tuposoft.com");
                EXPECT_EQ(result.size(), 1);
                EXPECT_EQ(result[0].rdata.mx, "mail.tuposoft.com");
            },
            detached);
    context_.run();
}

TEST_F(resolver_test, ptr) {
    co_spawn(
            context_,
            []() -> awaitable<void> {
                auto resolv = resolver{co_await this_coro::executor};
                co_await resolv.connect("1.1.1.1");
                const auto result = co_await resolv.query<dns_record_e::PTR>("1.1.1.1");
                EXPECT_EQ(result.size(), 1);
                EXPECT_EQ(result[0].rdata, "one.one.one.one");
            },
            detached);
    context_.run();
}
