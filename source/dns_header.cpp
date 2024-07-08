#include "dns_header.hpp"

#include <asio.hpp>

constexpr unsigned SINGLE_BIT_MASK = 1U;
constexpr unsigned OPCODE_MASK = 0xFU;
constexpr unsigned RCODE_MASK = 0xFU;

namespace tuposoft {
    auto tie_dns_header(const dns_header &header) {
        return std::tie(header.id, header.rd, header.tc, header.aa, header.opcode, header.qr, header.rcode, header.cd,
                        header.ad, header.z, header.ra, header.qdcount, header.ancount, header.nscount, header.arcount);
    }

    auto operator==(const dns_header &first, const dns_header &second) -> bool {
        const auto tied_first = tie_dns_header(first);
        const auto tied_second = tie_dns_header(second);
        return tied_first == tied_second;
    }

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
} // namespace tuposoft
