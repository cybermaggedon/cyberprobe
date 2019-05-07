
#ifndef TLS_UTILS_H
#define TLS_UTILS_H

#include <string>

namespace cybermon {
namespace tls_utils {
  std::string convertTLSVersion(uint8_t maj, uint8_t min);
}
}
#endif
