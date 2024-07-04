#include "starter.hpp"

#include <gtest/gtest.h>

TEST(starter, no_throws) {
    ASSERT_NO_THROW({ tuposoft::starter::hello("world"); });
}
