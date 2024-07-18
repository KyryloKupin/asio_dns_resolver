#include "qtype.hpp"

namespace tuposoft {
    auto operator<<(std::ostream &out, qtype record) -> decltype(out) {
        return out << static_cast<std::uint16_t>(record);
    }

    auto operator>>(std::istream &ins, qtype &record) -> decltype(ins) {
        std::uint16_t value = 0;
        ins >> value;
        record = static_cast<qtype>(value);
        return ins;
    }
} // namespace tuposoft
