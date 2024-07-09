#include "common.hpp"

#include <cstring>
#include <unordered_map>

using namespace tuposoft;

auto tuposoft::to_dns_label_format(const std::string &domain) -> std::vector<std::uint8_t> {
    auto label_format = std::vector<std::uint8_t>{};
    std::size_t start{};

    // ReSharper disable once CppDFAUnusedValue
    for (std::size_t end{}; (end = domain.find('.', start)) != std::string::npos; start = end + 1) {
        auto length = static_cast<std::uint8_t>(end - start);
        label_format.push_back(length);
        label_format.insert(label_format.end(), domain.begin() + static_cast<long int>(start),
                            domain.begin() + static_cast<long long int>(end));
    }

    if ((static_cast<unsigned>(domain.at(0)) & UPPER_TWO_BITS_MASK) == UPPER_TWO_BITS_MASK) {
        label_format.insert(label_format.end(), domain.begin() + static_cast<long int>(start), domain.end());
    } else {
        // Last label
        const auto length = static_cast<std::uint8_t>(domain.size() - start);
        label_format.push_back(length);
        label_format.insert(label_format.end(), domain.begin() + static_cast<long int>(start), domain.end());
        // Null terminator for the qname
        label_format.push_back(0);
    }

    return label_format;
}

/*
 * 1. Check next byte
 * 2. If the byte has two highest bits set, it's a pointer
 * 3. If it's a pointer, read the next byte, both bytes give the offset
 * 4. Set the input read position to the offset, read the label
 * 5. Otherwise, it's a label, read the label
 * 6. Repeat 1, 2, 3
 *
 *
 *
 *
 *
 *
 *
 */

auto tuposoft::from_dns_label_format(std::istream &input) -> std::string {
    auto result = std::string{};
    auto first_ptr_pos{-1};

    for (auto next_byte = static_cast<unsigned>(input.get()); next_byte != 0; next_byte = input.get()) {
        if ((next_byte & UPPER_TWO_BITS_MASK) != UPPER_TWO_BITS_MASK) {
            std::vector<char> buffer(next_byte);
            input.read(buffer.data(), next_byte);
            result += std::string{buffer.begin(), buffer.end()} + '.';
        } else {
            const unsigned next_pos =
                    (next_byte & LOWER_SIX_BITS_MASK) << FULL_BYTE | static_cast<unsigned>(input.get());

            if (first_ptr_pos == -1) {
                first_ptr_pos = std::max(first_ptr_pos, static_cast<int>(input.tellg()));
            }

            input.seekg(next_pos);
        }
    }

    if (first_ptr_pos != -1) {
        input.seekg(first_ptr_pos);
    }

    result.pop_back();

    return result;
}
