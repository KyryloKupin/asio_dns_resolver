#include "starter.hpp"

#include <fmt/format.h>

#include <iostream>

auto tuposoft::starter::hello(std::string someone) -> void { std::cout << fmt::format("Hello {}!\n", someone); }
