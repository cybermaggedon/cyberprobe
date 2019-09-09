
#include <cyberprobe/protocol/tls_key_exchange.h>
#include <cyberprobe/protocol/tls_exception.h>

#include <iomanip>
#include <iostream>
#include <arpa/inet.h>
#include <sstream>

using namespace cyberprobe::protocol;

#ifdef NOT_USED

namespace {

    std::string extract_hex_string(cybermon::pdu_iter start, cybermon::pdu_iter end)
    {
        std::ostringstream oss;
        oss << "0x";
        for (cybermon::pdu_iter iter=start;
             iter != end;
             ++iter)
            {
                oss << std::setw(2) << std::setfill('0') << std::hex  << static_cast<const uint16_t>(*iter);
            }
        return oss.str();
    }
}
#endif

void tls_key_exchange::server_ecdh(const pdu_slice& pduSlice, uint16_t length, protocol::tls_handshake_protocol::ecdh_ptr md)
{
    protocol::pdu_iter dataPtr = pduSlice.start;
    uint16_t dataLeft = length;

    md->curveType = *dataPtr;
    dataPtr += 1;
    dataLeft -= 1;

    switch (md->curveType)
        {
        case 1:
        {
            // following code should decode the curvetype based upon the RFC, but no data to test with,
            // so just survey
            return;

            // uint8_t primeLen = *dataPtr;
            // dataPtr += 1;
            // dataLeft -= 1;
            // std::string prime = extract_hex_string(dataPtr, dataPtr + primeLen);
            // dataPtr += primeLen;
            // dataLeft -= primeLen;
            // md->curveData.emplace_back("prime", prime);
            //
            // uint8_t curveALen = *dataPtr;
            // dataPtr += 1;
            // dataLeft -= 1;
            // std::string curveA = extract_hex_string(dataPtr, dataPtr + curveALen);
            // dataPtr += curveALen;
            // dataLeft -= curveALen;
            // md->curveData.emplace_back("curve-a", curveA);
            //
            // uint8_t curveBLen = *dataPtr;
            // dataPtr += 1;
            // dataLeft -= 1;
            // std::string curveB = extract_hex_string(dataPtr, dataPtr + curveBLen);
            // dataPtr += curveBLen;
            // dataLeft -= curveBLen;
            // md->curveData.emplace_back("curve-b", curveB);
            //
            // uint8_t ecpointLen = *dataPtr;
            // dataPtr += 1;
            // dataLeft -= 1;
            // std::string ecpoint = extract_hex_string(dataPtr, dataPtr + ecpointLen);
            // dataPtr += ecpointLen;
            // dataLeft -= ecpointLen;
            // md->curveData.emplace_back("ecpoint", ecpoint);
            //
            // uint8_t orderLen = *dataPtr;
            // dataPtr += 1;
            // dataLeft -= 1;
            // std::string order = extract_hex_string(dataPtr, dataPtr + orderLen);
            // dataPtr += orderLen;
            // dataLeft -= orderLen;
            // md->curveData.emplace_back("order", order);
            //
            // uint8_t cofactorLen = *dataPtr;
            // dataPtr += 1;
            // dataLeft -= 1;
            // std::string cofactor = extract_hex_string(dataPtr, dataPtr + cofactorLen);
            // dataPtr += cofactorLen;
            // dataLeft -= cofactorLen;
            // md->curveData.emplace_back("cofactor", cofactor);

            break;
        }
        case 2:
        {
            return;
            break;
        }
        case 3:
        {
            const uint16_t curve = ntohs(*reinterpret_cast<const uint16_t*>(&dataPtr[0]));
            dataPtr += 2;
            dataLeft -= 2;
            NamedCurve nc;

            if ((curve < 26 && curve != 0) || curve == 0xFF01 || curve == 0xFF02)
                {
                    nc = static_cast<NamedCurve>(curve);
                }
            else
                {
                    nc = NamedCurve::reserved;
                }
            md->curveData.emplace_back("name", to_string(nc));
            break;
        }
        default:
        {
            return;
            break;
        }
        }

    uint8_t pointLen = *dataPtr;
    dataPtr += 1;
    dataLeft -= 1;

    if (pointLen > dataLeft)
        {
            throw tls_exception("TLS ECDH Error - Not enough room for public key point");
        }

    md->pubKey.reserve(pointLen);
    md->pubKey.insert(md->pubKey.end(), dataPtr, dataPtr + pointLen);
    dataPtr += pointLen;
    dataLeft -= pointLen;

    md->sigHashAlgo = dataPtr[0];
    dataPtr += 1;
    dataLeft -= 1;
    md->sigAlgo = dataPtr[0];
    dataPtr += 1;
    dataLeft -= 1;

    const uint16_t hashLen =  ntohs(*reinterpret_cast<const uint16_t*>(&dataPtr[0]));
    dataPtr += 2;
    dataLeft -= 2;

    if (hashLen > dataLeft) {
        throw tls_exception("TLS ECDH Error - Not enough room for signature hash");
    }

    std::ostringstream oss;
    for (protocol::pdu_iter iter=dataPtr;
         iter != dataPtr+hashLen;
         ++iter)
        {
            oss << std::setw(2) << std::setfill('0') << std::hex  << static_cast<const uint16_t>(*iter);
        }
    md->hash = oss.str();
    dataPtr += hashLen;
    dataLeft -= hashLen;

}

void tls_key_exchange::client_ecdh(const pdu_slice& pduSlice, uint16_t length, std::vector<uint8_t>& key)
{
    protocol::pdu_iter dataPtr = pduSlice.start;
    uint16_t dataLeft = length;

    uint8_t pointLen = *dataPtr;
    dataPtr += 1;
    dataLeft -= 1;

    if (pointLen > dataLeft)
        {
            throw tls_exception("TLS ECDH Error - Not enough room for public key point");
        }

    key.reserve(pointLen);
    key.insert(key.end(), dataPtr, dataPtr + pointLen);

}

std::string tls_key_exchange::to_string(const NamedCurve nc) {
    switch (nc)
        {
        case sect163k1:
            return "sect163k1";
            break;
        case sect163r1:
            return "sect163r1";
            break;
        case sect163r2:
            return "sect163r2";
            break;
        case sect193r1:
            return "sect193r1";
            break;
        case sect193r2:
            return "sect193r2";
            break;
        case sect233k1:
            return "sect233k1";
            break;
        case sect233r1:
            return "sect233r1";
            break;
        case sect239k1:
            return "sect239k1";
            break;
        case sect283k1:
            return "sect283k1";
            break;
        case sect283r1:
            return "sect283r1";
            break;
        case sect409k1:
            return "sect409k1";
            break;
        case sect409r1:
            return "sect409r1";
            break;
        case sect571k1:
            return "sect571k1";
            break;
        case sect571r1:
            return "sect571r1";
            break;
        case secp160k1:
            return "secp160k1";
            break;
        case secp160r1:
            return "secp160r1";
            break;
        case secp160r2:
            return "secp160r2";
            break;
        case secp192k1:
            return "secp192k1";
            break;
        case secp192r1:
            return "secp192r1";
            break;
        case secp224k1:
            return "secp224k1";
            break;
        case secp224r1:
            return "secp224r1";
            break;
        case secp256k1:
            return "secp256k1";
            break;
        case secp256r1:
            return "secp256r1";
            break;
        case secp384r1:
            return "secp384r1";
            break;
        case secp521r1:
            return "secp521r1";
            break;
        case arbitrary_explicit_prime_curves:
            return "arbitrary_explicit_prime_curves";
            break;
        case arbitrary_explicit_char2_curves:
            return "arbitrary_explicit_char2_curves";
            break;
        case reserved:
            return "reserved";
            break;
        }
    return "reserved";
}

