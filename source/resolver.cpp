#include "resolver.hpp"

using namespace tuposoft;

auto resolver::generate_id() -> decltype(generate_id()) {
    std::random_device rand;
    std::mt19937 gen(rand());
    return std::uniform_int_distribution<unsigned short>(0, std::numeric_limits<unsigned short>::max())(gen);
}
