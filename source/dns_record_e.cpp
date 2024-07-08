#include "dns_record_e.hpp"

namespace tuposoft {
    auto operator<<(std::ostream &out, dns_record_e record) -> decltype(out) {
        return out << static_cast<std::uint16_t>(record);
    }

    auto operator>>(std::istream &ins, dns_record_e &record) -> decltype(ins) {
        std::uint16_t value = 0;
        ins >> value;
        record = static_cast<dns_record_e>(value);
        return ins;
    }
} // namespace tuposoft
