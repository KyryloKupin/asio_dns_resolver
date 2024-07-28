#include "resolver.hpp"

#include "boost/asio.hpp"
#include "boost/enable_shared_from_this.hpp"
#include "gtest/gtest.h"

using namespace KyryloKupin::asio::dns;
using namespace boost::asio;

class resolver_test : public testing::Test {
protected:
    io_context context_;

    template<qtype T>
    auto query_test(std::tuple<std::string, std::size_t, std::vector<typename rdata<T>::type>> data)
            -> awaitable<void> {
        auto [name, size, expected] = data;
        auto resolv = resolver{co_await this_coro::executor};
        co_await resolv.connect("1.1.1.1");
        const auto result = co_await resolv.query<T>(name);
        EXPECT_EQ(result.size(), size);
        for (int i = 0; i < result.size(); ++i) {
            EXPECT_EQ(result[i].rdata, expected[i]);
        }
    };
};

TEST_F(resolver_test, a) {
    co_spawn(context_, query_test<qtype::A>({"tuposoft.com", 1, {"217.160.29.228"}}), detached);
    context_.run();
}

TEST_F(resolver_test, mx) {
    constexpr auto PREFERENCE = 10;
    co_spawn(context_, query_test<qtype::MX>({"tuposoft.com", 1, {{PREFERENCE, "mail.tuposoft.com"}}}), detached);
    context_.run();
}

TEST_F(resolver_test, ptr) {
    co_spawn(context_, query_test<qtype::PTR>({"1.1.1.1", 1, {"one.one.one.one"}}), detached);
    context_.run();
}

TEST_F(resolver_test, ns) {
    co_spawn(context_,
             query_test<qtype::NS>({"tuposoft.com", 2, {"benedict.ns.cloudflare.com", "gabriella.ns.cloudflare.com"}}),
             detached);
    context_.run();
}

TEST_F(resolver_test, cname) {
    co_spawn(context_, query_test<qtype::CNAME>({"bucketname.s3.amazonaws.com", 1, {"s3-1-w.amazonaws.com"}}),
             detached);
    context_.run();
}
