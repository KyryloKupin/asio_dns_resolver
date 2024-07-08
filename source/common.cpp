#include "common.hpp"

#include <array>
#include <cstring>

using namespace tuposoft;

auto tuposoft::to_dns_label_format(const std::string &domain) -> std::vector<std::uint8_t> {
    auto label_format = std::vector<std::uint8_t>{};
    std::size_t start{};

    // ReSharper disable once CppDFAUnusedValue
    for (std::size_t end{}; (end = domain.find('.', start)) != std::string::npos; start = end + 1) {
        auto length = static_cast<std::uint8_t>(end - start);
        label_format.push_back(length);
        label_format.insert(label_format.end(), domain.begin() + static_cast<long int>(start),
                            domain.begin() + static_cast<long int>(end));
    }

    if ((static_cast<unsigned>(domain.at(0)) & UPPER_SIX_BITS_MASK) == UPPER_SIX_BITS_MASK) {
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

auto tuposoft::from_dns_label_format(std::istream &input) -> std::string {
    auto qname_buffer = std::vector<char>{};

    bool is_ptr = false;
    while (true) {
        const auto length = read_from_stream_and_copy<std::uint8_t>(input);

        if (length == 0) {
            if (is_ptr) {
                input.unget();
            }

            break; // End of qname
        }

        if ((length & UPPER_SIX_BITS_MASK) == UPPER_SIX_BITS_MASK) {
            constexpr auto LOWER_SIX_BITS_MASK = 0x3FU;
            const auto ptr = read_from_stream_and_copy<std::uint8_t>(input);
            const auto current_pos = input.tellg();
            input.seekg((length & LOWER_SIX_BITS_MASK) << BYTE_SIZE | ptr);
            auto pointed_labes = from_dns_label_format(input);
            qname_buffer.insert(qname_buffer.end(), pointed_labes.begin(), pointed_labes.end());
            qname_buffer.push_back('.');
            input.seekg(current_pos);
            is_ptr = true;
        } else {
            auto label = std::vector<char>(length);
            input.read(label.data(), length);
            qname_buffer.insert(qname_buffer.end(), label.begin(), label.end());
            qname_buffer.push_back('.');
            is_ptr = false;
        }
    }

    if (!qname_buffer.empty()) {
        qname_buffer.pop_back(); // Remove the last dot
    }

    return {qname_buffer.begin(), qname_buffer.end()};
}
