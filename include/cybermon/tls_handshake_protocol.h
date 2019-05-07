
#ifndef CYBERMON_TLS_HANDSHAKE_PROTOCOL_H
#define CYBERMON_TLS_HANDSHAKE_PROTOCOL_H

#include <cybermon/pdu.h>

#include <string>
#include <vector>
#include <iterator>
#include <iostream>
#include <memory>

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
  cipher_suite() {}
  cipher_suite(uint16_t id, std::string name) : id(id), name(name) {}
  cipher_suite(const cipher_suite& other) : id(other.id), name(other.name) {}
};

struct compression_method {
  uint8_t id;
  std::string name;
  compression_method() {}
  compression_method(uint8_t id, std::string name) : id(id), name(name) {}
  compression_method(const compression_method& other) : id(other.id), name(other.name) {}
};

struct hello_base {
  std::string version;
  uint32_t randomTimestamp;
  uint8_t random[28];
  std::string sessionID;

  hello_base() {}
  hello_base(const hello_base& other)
  : version(other.version), randomTimestamp(other.randomTimestamp),
    sessionID(other.sessionID)
  {
    // deep copy data
    std::copy(std::begin(other.random), std::end(other.random), std::begin(random));
  }
};

struct client_hello_data : public hello_base {
  std::vector<cipher_suite> cipherSuites;
  std::vector<compression_method> compressionMethods;
  std::vector<extension> extensions;

  client_hello_data() {}
  client_hello_data(const client_hello_data& other) : hello_base(other)
  {
    // deep copy data
    cipherSuites.reserve(other.cipherSuites.size());
    cipherSuites.insert(cipherSuites.end(), other.cipherSuites.begin(), other.cipherSuites.end());
    compressionMethods.reserve(other.compressionMethods.size());
    compressionMethods.insert(compressionMethods.end(), other.compressionMethods.begin(),
      other.compressionMethods.end());
    extensions.reserve(other.extensions.size());
    extensions.insert(extensions.end(), other.extensions.begin(), other.extensions.end());
  }
};

struct server_hello_data : public hello_base  {
  cipher_suite cipherSuite;
  compression_method compressionMethod;
  std::vector<extension> extensions;

  server_hello_data() {}
  server_hello_data(const server_hello_data& other)
  : hello_base(other), cipherSuite(other.cipherSuite),
    compressionMethod(other.compressionMethod)
  {
    // deep copy data
    extensions.reserve(other.extensions.size());
    extensions.insert(extensions.end(), other.extensions.begin(), other.extensions.end());
  }
};

struct curve_data {
  std::string name;
  std::string value;

  curve_data(std::string n, std::string v) : name(n), value(v)
  {}
};

struct ecdh_data {
  uint8_t curveType;
  std::vector<curve_data> curveData;
  std::vector<uint8_t> pubKey;
  uint8_t sigHashAlgo;
  uint8_t sigAlgo;
  std::string hash;
};

struct dhanon_data {
  std::vector<uint8_t> p;
  std::vector<uint8_t> g;
  std::vector<uint8_t> pubKey;
};

struct dhrsa_data : public dhanon_data {
  std::vector<uint8_t> sig;
};

using ecdh_ptr = std::shared_ptr<ecdh_data>;
using dhrsa_ptr = std::shared_ptr<dhrsa_data>;
using dhanon_ptr = std::shared_ptr<dhanon_data>;

struct key_exchange_data {
  ecdh_ptr ecdh;
  dhrsa_ptr dhrsa;
  dhanon_ptr dhanon;
};

struct signature_algorithm {
  uint8_t sigHashAlgo;
  uint8_t sigAlgo;

  signature_algorithm(uint8_t h, uint8_t a) : sigHashAlgo(h), sigAlgo(a)
  {}
};

struct certificate_request_data {
  std::vector<std::string> certTypes;
  std::vector<signature_algorithm> sigAlgos;
  std::vector<uint8_t> distinguishedNames;
};


} // tls_handshake_protocol
} // cybermon

#endif
