
#ifndef TLS_KEY_EXCHANGE_H
#define TLS_KEY_EXCHANGE_H

#include <cybermon/tls_handshake_protocol.h>
#include <cybermon/pdu.h>

#include <stdint.h>
#include <string>
#include <vector>

namespace cybermon {
    namespace tls_key_exchange {

        void server_ecdh(const pdu_slice& pduSlice, uint16_t length, tls_handshake_protocol::ecdh_ptr md);
        void client_ecdh(const pdu_slice& pduSlice, uint16_t length, std::vector<uint8_t>& key);

        enum NamedCurve {
            sect163k1=1, sect163r1=2, sect163r2=3,
            sect193r1=4, sect193r2=5, sect233k1=6,
            sect233r1=7, sect239k1=8, sect283k1=9,
            sect283r1=10, sect409k1=11, sect409r1=12,
            sect571k1=13, sect571r1=14, secp160k1=15,
            secp160r1=16, secp160r2=17, secp192k1=18,
            secp192r1=19, secp224k1=20, secp224r1=21,
            secp256k1=22, secp256r1=23, secp384r1=24,
            secp521r1=25,
            arbitrary_explicit_prime_curves=0xFF01,
            arbitrary_explicit_char2_curves=0xFF02,
            reserved
        };

        std::string to_string(const NamedCurve nc);

    } // namespace tls_key_exchange
} // namespace cybermon

#endif
