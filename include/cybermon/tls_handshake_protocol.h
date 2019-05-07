
#ifndef CYBERMON_TLS_HANDSHAKE_PROTOCOL_H
#define CYBERMON_TLS_HANDSHAKE_PROTOCOL_H

#include <string>
#include <vector>
#include <iterator>

namespace cybermon {
namespace tls_handshake_protocol {

struct extension {
  uint16_t type;
  std::string name;
  uint16_t len;
  std::vector<uint8_t> data;
  extension(uint16_t type, std::string name, uint16_t len, pdu_iter start)
    : type(type), name(name), len(len), data(start, start+len) {}
  extension(const extension& other)
    : type(other.type), name(other.name), len(other.len)
  {
    data.reserve(other.data.size());
    data.insert(data.end(), other.data.begin(), other.data.end());
  }
};


struct cipher_suite {
  uint16_t id;
  std::string name;
  cipher_suite(uint16_t id, std::string name) : id(id), name(name) {}
  cipher_suite(const cipher_suite& other) : id(other.id), name(other.name) {}
};

struct compression_method {
  uint8_t id;
  std::string name;
  compression_method(uint8_t id, std::string name) : id(id), name(name) {}
  compression_method(const compression_method& other) : id(other.id), name(other.name) {}
};


struct client_hello_data {
  std::string version;
  uint32_t randomTimestamp;
  uint8_t random[28];
  std::string sessionID;
  std::vector<cipher_suite> cipherSuites;
  std::vector<compression_method> compressionMethods;
  std::vector<extension> extensions;

  client_hello_data() {}
  client_hello_data(const client_hello_data& other)
  : version(other.version), randomTimestamp(other.randomTimestamp),
    sessionID(other.sessionID)
  {
    // deep copy data
    std::copy(std::begin(other.random), std::end(other.random), std::begin(random));
    cipherSuites.reserve(other.cipherSuites.size());
    cipherSuites.insert(cipherSuites.end(), other.cipherSuites.begin(), other.cipherSuites.end());
    compressionMethods.reserve(other.compressionMethods.size());
    compressionMethods.insert(compressionMethods.end(), other.compressionMethods.begin(),
      other.compressionMethods.end());
    extensions.reserve(other.extensions.size());
    extensions.insert(extensions.end(), other.extensions.begin(), other.extensions.end());
  }
};

} // tls_handshake_protocol
} // cybermon

#endif
