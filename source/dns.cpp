#include "dns.hpp"

namespace tuposoft {
    constexpr auto BYTE_SIZE = std::uint8_t{0x08U};
    constexpr auto FULL_BYTE = std::uint8_t{0xFF};

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
        // Last label
        const auto length = static_cast<std::uint8_t>(domain.size() - start);
        label_format.push_back(length);
        label_format.insert(label_format.end(), domain.begin() + static_cast<long int>(start), domain.end());
        // Null terminator for the qname
        label_format.push_back(0);

        return label_format;
    }

    auto from_dns_label_format(std::istream &input) -> std::string {
        auto qname_buffer = std::vector<char>{};

        while (true) {
            const auto length = read_from_stream_and_copy<std::uint8_t>(input);

            if (length == 0) {
                break; // End of qname
            }

            if (constexpr auto UPPER_SIX_BITS_MASK = 0xC0U; (length & UPPER_SIX_BITS_MASK) == UPPER_SIX_BITS_MASK) {
                constexpr auto LOWER_SIX_BITS_MASK = 0x3FU;
                const auto ptr = read_from_stream_and_copy<std::uint8_t>(input);
                const auto current_pos = input.tellg();
                input.seekg((length & LOWER_SIX_BITS_MASK) << BYTE_SIZE | ptr);
                auto pointed_labes = from_dns_label_format(input);
                qname_buffer.insert(qname_buffer.end(), pointed_labes.begin(), pointed_labes.end());
                qname_buffer.push_back('.');
                input.seekg(current_pos);
            } else {
                auto label = std::vector<char>(length);
                input.read(label.data(), length);
                qname_buffer.insert(qname_buffer.end(), label.begin(), label.end());
                qname_buffer.push_back('.');
            }
        }

        if (!qname_buffer.empty()) {
            qname_buffer.pop_back(); // Remove the last dot
        }

        return {qname_buffer.begin(), qname_buffer.end()};
    }

    template<typename T>
    auto tuposoft::read_from_stream_and_copy(std::istream &input) -> T {
        std::array<char, sizeof(T)> buffer{};
        input.read(buffer.data(), sizeof(T));

        T object{};
        std::memcpy(&object, buffer.data(), sizeof(T));

        return object;
    }

    template<typename T = std::uint16_t>
    auto read_big_endian(std::istream &input) -> T {
        T result{};
        for (int i = 0; i < sizeof(T); ++i) {
            result <<= BYTE_SIZE;
            result |= static_cast<T>(input.get()) & FULL_BYTE;
        }
        return result;
    }

    auto get_flag_bits(const unsigned value, const unsigned position, const unsigned mask) -> unsigned {
        return (value >> position) & mask;
    }

    // dns_header::dns_header() {
    //     auto generator = std::mt19937{std::random_device{}()};
    //     id = std::uniform_int_distribution<std::uint16_t>{
    //         0, std::numeric_limits<std::uint16_t>::max()
    //     }(generator);
    // }

    enum flag_positions : std::uint8_t {
        rd_position = 8U,
        tc_position = 9U,
        aa_position = 10U,
        opcode_position = 11U,
        qr_position = 15U,
        rcode_position = 0U,
        cd_position = 4U,
        ad_position = 5U,
        z_position = 6U,
        ra_position = 7U,
    };

    constexpr unsigned SINGLE_BIT_MASK = 1U;
    constexpr unsigned OPCODE_MASK = 0xFU;
    constexpr unsigned RCODE_MASK = 0xFU;

    auto dns_header::operator==(const dns_header &other) const -> bool { return tied() == other.tied(); }

    auto operator>>(std::istream &input, dns_header &header) -> decltype(input) {
        header.id = ntohs(read_from_stream_and_copy<std::uint16_t>(input));

        const std::uint16_t flags = ntohs(read_from_stream_and_copy<std::uint16_t>(input));

        header.rd = flags >> rd_position & SINGLE_BIT_MASK;
        header.tc = flags >> tc_position & SINGLE_BIT_MASK;
        header.aa = flags >> aa_position & SINGLE_BIT_MASK;
        header.opcode = flags >> opcode_position & OPCODE_MASK;
        header.qr = flags >> qr_position & SINGLE_BIT_MASK;
        header.rcode = flags & RCODE_MASK;
        header.cd = flags >> cd_position & SINGLE_BIT_MASK;
        header.ad = flags >> ad_position & SINGLE_BIT_MASK;
        header.z = flags >> z_position & SINGLE_BIT_MASK;
        header.ra = flags >> ra_position & SINGLE_BIT_MASK;

        header.qdcount = ntohs(read_from_stream_and_copy<std::uint16_t>(input));
        header.ancount = ntohs(read_from_stream_and_copy<std::uint16_t>(input));
        header.nscount = ntohs(read_from_stream_and_copy<std::uint16_t>(input));
        header.arcount = ntohs(read_from_stream_and_copy<std::uint16_t>(input));

        return input;
    }

    auto operator<<(std::ostream &output, const dns_header &header) -> decltype(output) {
        const std::uint16_t flags = header.rd << rd_position | header.tc << tc_position | header.aa << aa_position |
                                    header.opcode << opcode_position | header.qr << qr_position |
                                    header.rcode << rcode_position | header.cd << cd_position |
                                    header.ad << ad_position | header.z << z_position | header.ra << ra_position;

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

    auto operator<<(std::ostream &output, const dns_answer &answer) -> decltype(output) {
        const auto label_format = to_dns_label_format(answer.name);
        output.write(reinterpret_cast<const char *>(label_format.data()),
                     static_cast<std::streamsize>(label_format.size()));

        // Write type, cls, ttl, rdlength, and rdata
        const auto type_network = htons(static_cast<std::uint16_t>(answer.type));
        const auto cls_network = htons(answer.cls);
        const auto ttl_network = htonl(answer.ttl);
        const auto rdlength_network = htons(answer.rdlength);

        output.write(reinterpret_cast<const char *>(&type_network), sizeof(type_network));
        output.write(reinterpret_cast<const char *>(&cls_network), sizeof(cls_network));
        output.write(reinterpret_cast<const char *>(&ttl_network), sizeof(ttl_network));
        output.write(reinterpret_cast<const char *>(&rdlength_network), sizeof(rdlength_network));
        output.write(reinterpret_cast<const char *>(answer.rdata.data()),
                     static_cast<std::streamsize>(answer.rdata.size()));

        return output;
    }

    auto operator>>(std::istream &input, dns_answer &answer) -> decltype(input) {
        answer.name = from_dns_label_format(input);

        // Read type, cls, ttl, rdlength, and rdata
        const auto type_network = read_big_endian(input);
        const auto cls_network = read_big_endian(input);
        const auto ttl_network = read_big_endian<std::uint32_t>(input);
        const auto rdlength_network = read_big_endian(input);

        answer.type = static_cast<dns_record_e>(ntohs(type_network));
        answer.cls = ntohs(cls_network);
        answer.ttl = ntohl(ttl_network);
        answer.rdlength = ntohs(rdlength_network);

        auto buffer = std::vector<char>(answer.rdlength);
        input.read(buffer.data(), answer.rdlength);
        answer.rdata = std::vector<std::uint8_t>{buffer.begin(), buffer.end()};

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
} // namespace tuposoft
