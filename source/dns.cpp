#include "dns.hpp"

#include <asio.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <ios>
#include <istream>
#include <ostream>
#include <string>
#include <vector>


namespace tuposoft {
    constexpr auto BYTE_SIZE = std::uint8_t{0x08U};
    constexpr auto FULL_BYTE = std::uint8_t{0xFF};
    constexpr auto UPPER_SIX_BITS_MASK = std::uint8_t{0xC0U};

    auto to_dns_label_format(const std::string &domain) -> std::vector<std::uint8_t> {
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

    auto from_dns_label_format(std::istream &input) -> std::string {
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

    template<typename T>
    auto read_from_stream_and_copy(std::istream &input) -> T {
        std::array<char, sizeof(T)> buffer{};
        input.read(buffer.data(), sizeof(T));

        T object{};
        std::memcpy(&object, buffer.data(), sizeof(T));

        return object;
    }

    template<typename T>
    auto read_big_endian(std::istream &input) -> T {
        T result{};
        for (int i = 0; i < sizeof(T); ++i) {
            result <<= BYTE_SIZE;
            result |= static_cast<T>(input.get()) & FULL_BYTE;
        }
        return result;
    }

    // dns_header::dns_header() {
    //     auto generator = std::mt19937{std::random_device{}()};
    //     id = std::uniform_int_distribution<std::uint16_t>{
    //         0, std::numeric_limits<std::uint16_t>::max()
    //     }(generator);
    // }

    enum flag_positions : unsigned char {
        RD_POSITION = 8U,
        TC_POSITION = 9U,
        AA_POSITION = 10U,
        OPCODE_POSITION = 11U,
        QR_POSITION = 15U,
        RCODE_POSITION = 0U,
        CD_POSITION = 4U,
        AD_POSITION = 5U,
        Z_POSITION = 6U,
        RA_POSITION = 7U,
    };

    constexpr unsigned SINGLE_BIT_MASK = 1U;
    constexpr unsigned OPCODE_MASK = 0xFU;
    constexpr unsigned RCODE_MASK = 0xFU;

    auto dns_header::operator==(const dns_header &other) const -> bool { return tied() == other.tied(); }

    auto operator>>(std::istream &input, dns_header &header) -> decltype(input) {
        header.id = ntohs(read_from_stream_and_copy<std::uint16_t>(input));

        const unsigned short flags = ntohs(read_from_stream_and_copy<std::uint16_t>(input));

        header.rd = flags >> RD_POSITION & SINGLE_BIT_MASK;
        header.tc = flags >> TC_POSITION & SINGLE_BIT_MASK;
        header.aa = flags >> AA_POSITION & SINGLE_BIT_MASK;
        header.opcode = flags >> OPCODE_POSITION & OPCODE_MASK;
        header.qr = flags >> QR_POSITION & SINGLE_BIT_MASK;
        header.rcode = flags & RCODE_MASK;
        header.cd = flags >> CD_POSITION & SINGLE_BIT_MASK;
        header.ad = flags >> AD_POSITION & SINGLE_BIT_MASK;
        header.z = flags >> Z_POSITION & SINGLE_BIT_MASK;
        header.ra = flags >> RA_POSITION & SINGLE_BIT_MASK;

        header.qdcount = ntohs(read_from_stream_and_copy<std::uint16_t>(input));
        header.ancount = ntohs(read_from_stream_and_copy<std::uint16_t>(input));
        header.nscount = ntohs(read_from_stream_and_copy<std::uint16_t>(input));
        header.arcount = ntohs(read_from_stream_and_copy<std::uint16_t>(input));

        return input;
    }

    auto operator<<(std::ostream &output, const dns_header &header) -> decltype(output) {
        const std::uint16_t flags = header.rd << RD_POSITION | header.tc << TC_POSITION | header.aa << AA_POSITION |
                                    header.opcode << OPCODE_POSITION | header.qr << QR_POSITION |
                                    header.rcode << RCODE_POSITION | header.cd << CD_POSITION |
                                    header.ad << AD_POSITION | header.z << Z_POSITION | header.ra << RA_POSITION;

        const auto id_network = htons(header.id);
        const auto flags_network = htons(flags);
        const auto qdcount_network = htons(header.qdcount);
        const auto ancount_network = htons(header.ancount);
        const auto nscount_network = htons(header.nscount);
        const auto arcount_network = htons(header.arcount);

        output.write(reinterpret_cast<const char *>(&id_network), sizeof(id_network));
        output.write(reinterpret_cast<const char *>(&flags_network), sizeof(flags_network));
        output.write(reinterpret_cast<const char *>(&qdcount_network), sizeof(qdcount_network));
        output.write(reinterpret_cast<const char *>(&ancount_network), sizeof(ancount_network));
        output.write(reinterpret_cast<const char *>(&nscount_network), sizeof(nscount_network));
        output.write(reinterpret_cast<const char *>(&arcount_network), sizeof(arcount_network));

        return output;
    }

    auto operator<<(std::ostream &out, dns_record_e record) -> decltype(out) {
        return out << static_cast<std::uint16_t>(record);
    }

    auto operator>>(std::istream &ins, dns_record_e &record) -> decltype(ins) {
        std::uint16_t value = 0;
        ins >> value;
        record = static_cast<dns_record_e>(value);
        return ins;
    }

    auto dns_question::operator==(const dns_question &other) const -> bool { return tied() == other.tied(); }

    auto operator<<(std::ostream &output, const dns_question &question) -> decltype(output) {
        const auto label_format = to_dns_label_format(question.qname);
        output.write(std::string{label_format.begin(), label_format.end()}.c_str(),
                     static_cast<std::streamsize>(label_format.size()));

        // Write qtype and qclass
        const auto qtype_network = htons(static_cast<std::uint16_t>(question.qtype));
        const auto qclass_network = htons(question.qclass);

        output.write(reinterpret_cast<const char *>(&qtype_network), sizeof(qtype_network));
        output.write(reinterpret_cast<const char *>(&qclass_network), sizeof(qclass_network));

        return output;
    }

    auto operator>>(std::istream &input, dns_question &question) -> decltype(input) {
        question.qname = from_dns_label_format(input);

        const auto qtype_network = read_from_stream_and_copy<std::uint16_t>(input);
        const auto qclass_network = read_from_stream_and_copy<std::uint16_t>(input);

        question.qtype = static_cast<dns_record_e>(ntohs(qtype_network));
        question.qclass = ntohs(qclass_network);

        return input;
    }

    auto dns_answer::operator==(const dns_answer &other) const -> bool { return tied() == other.tied(); }

    auto operator>>(std::istream &input, dns_answer &answer) -> decltype(input) {
        answer.name = from_dns_label_format(input);

        // Read type, cls, ttl, rdlength, and rdata
        const auto type_network = read_big_endian<std::uint16_t>(input);
        const auto cls_network = read_big_endian<std::uint16_t>(input);
        const auto ttl_network = read_big_endian<std::uint32_t>(input);
        const auto rdlength_network = read_big_endian<std::uint16_t>(input);

        answer.type = static_cast<dns_record_e>(type_network);
        answer.cls = cls_network;
        answer.ttl = ttl_network;
        answer.rdlength = rdlength_network;

        switch (answer.type) {
            case dns_record_e::A:
            case dns_record_e::NS:
            case dns_record_e::CNAME:
            case dns_record_e::SOA:
            case dns_record_e::PTR:
            case dns_record_e::MX:
                answer.parse_mx(input);
                break;
            case dns_record_e::TXT:
            case dns_record_e::AAAA:
            case dns_record_e::SRV:
            case dns_record_e::OPT:
            case dns_record_e::DS:
            case dns_record_e::RRSIG:
            case dns_record_e::NSEC:
            case dns_record_e::DNSKEY:
                break;
        }

        return input;
    }

    auto dns_query::operator==(const dns_query &other) const -> bool { return tied() == other.tied(); }

    auto operator<<(std::ostream &output, const dns_query &request) -> decltype(output) {
        return output << request.header << request.question;
    }

    auto operator>>(std::istream &input, dns_query &request) -> decltype(input) {
        input >> request.header;
        input >> request.question;
        return input;
    }

    auto dns_response::operator==(const dns_response &other) const -> bool { return tied() == other.tied(); }

    auto operator>>(std::istream &input, mx_rdata &mx_rdata) -> decltype(input) {
        mx_rdata.preference = read_big_endian(input);
        mx_rdata.mx = from_dns_label_format(input);
        return input;
    }

    auto operator>>(std::istream &input, dns_response &response) -> decltype(input) {
        input >> response.header;
        input >> response.question;
        input >> response.answer;

        return input;
    }

    auto mx_rdata::operator==(const mx_rdata &other) const -> bool { return tied() == other.tied(); }
} // namespace tuposoft
