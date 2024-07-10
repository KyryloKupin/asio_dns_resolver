#include "dns_answer.hpp"

#include <tuple>

using namespace tuposoft;

// auto tuposoft::tie_dns_answer(const dns_answer &answer) {
//     return std::tie(answer.name, answer.type, answer.cls, answer.ttl, answer.rdlength, answer.rdata);
// }
//
// auto tuposoft::operator==(const dns_answer &first, const dns_answer &second) -> bool {
//     return tie_dns_answer(first) == tie_dns_answer(second);
// }
